//! HiddenForge 3.0 in-image runtime: one multi-call binary.
//!
//! What it does depends on the name it is started as:
//!
//!   entrypoint.py        the image ENTRYPOINT: an operator subcommand
//!                        (`docker run <image> show ...`), else PID 1 (boot Tor)
//!   hiddenforge          the in-image operator CLI
//!   hiddenforge-guards   bandguards + rendguard (started by the supervisor)
//!   healthcheck.py       the healthcheck (also reached as `python3 <path>`)
//!   vanity.py            the vanity-address generator
//!   su-exec, python3, cat, sh, test, true
//!                        the exact 2.x forms that compose files, deploy
//!                        scripts and older CLIs run; nothing else (compat.rs)
mod cli;
mod clientauth;
mod compat;
mod fsops;
mod guards;
mod health;
mod keycrypt;
mod landlock;
mod privs;
mod py;
mod sealed;
mod sha3;
mod supervisor;
mod torrc;
mod vanguards;

use py::Json;
use std::time::Duration;

/// `docker run <image> <cmd>` names that run an operator command instead of booting.
const SUBCOMMANDS: &[&str] = &[
    "setup",
    "show",
    "doctor",
    "version",
    "info",
    "vanity",
    "encrypt-key",
    "decrypt-key",
    "backup",
    "restore",
    "rotate",
    "unseal-keys",
    "client-auth",
];
/// Subcommands that read the tor-owned key directories, so they run as tor.
const AS_TOR: &[&str] = &["show", "doctor"];

fn torrc_preview() -> i32 {
    let env = torrc::python_environ();
    let t = torrc::build(&env, &torrc::libc_resolve);
    let strs = |v: &[String]| Json::Arr(v.iter().map(|s| Json::Str(s.clone())).collect());
    let doc = Json::obj()
        .with("content", t.content.clone().into())
        .with("hs_dirs", strs(&t.hs_dirs))
        .with("dropped", strs(&t.dropped))
        .with(
            "resolved",
            Json::Obj(
                t.resolved
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::Str(v.clone())))
                    .collect(),
            ),
        )
        .with("unresolved", strs(&t.unresolved))
        .with("log", strs(&t.log));
    println!("{}", py::dumps(&doc, false, None));
    0
}

fn healthcheck(args: &[String]) -> i32 {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        [] => health::main_check(false),
        ["--json"] => health::main_check(true),
        ["--watch-uploads"] => health::watch_uploads(
            health::UPLOADS_FILE,
            health::CONTROL_SOCKET,
            Duration::from_secs(60),
        ),
        _ => {
            eprintln!("usage: healthcheck.py [-h] [--json] [--watch-uploads]");
            2
        }
    }
}

/// The in-image `hiddenforge` CLI, plus the supervisor's internal probes.
fn hiddenforge(args: &[String]) -> i32 {
    let Some((cmd, rest)) = args.split_first() else {
        eprintln!("usage: hiddenforge <command> [options]   (see `hiddenforge info`)");
        return 2;
    };
    match (
        cmd.as_str(),
        rest.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
    ) {
        ("__true", []) => 0,
        ("__is-socket", [p]) => compat::test(&["-S".into(), (*p).to_string()]),
        // Run as the tor user by the supervisor: the public hostname file only.
        ("__keys", [op, name]) => sealed::helper(op, name),
        ("__read-hostname", [p])
            if (p.starts_with("/var/lib/tor/hidden_service/")
                || p.starts_with("/var/lib/tor/hs-ram/"))
                && p.ends_with("/hostname")
                && !p.contains("/../") =>
        {
            match fsops::read_small_regular_file(p, fsops::ADDRESS_FILE_MAX) {
                Ok(d) => {
                    use std::io::Write;
                    i32::from(std::io::stdout().write_all(&d).is_err())
                }
                Err(_) => 1,
            }
        }
        // Run as the tor user by the supervisor, which holds no CAP_KILL.
        ("__kill", [pid, sig]) => match (pid.parse::<i32>(), sig.parse::<i32>()) {
            (Ok(p), Ok(s))
                if p > 1 && (s == libc::SIGTERM || s == libc::SIGINT || s == libc::SIGKILL) =>
            {
                // SAFETY: kill(2); the kernel enforces that we only reach our own processes.
                i32::from(unsafe { libc::kill(p, s) } != 0)
            }
            _ => 2,
        },
        ("torrc-preview", []) => torrc_preview(),
        ("healthcheck", _) => healthcheck(rest),
        _ => {
            if AS_TOR.contains(&cmd.as_str()) && privs::is_root() && root_cannot_reach_keys() {
                // Rootless Podman without DAC_OVERRIDE: root cannot traverse the
                // tor-owned /var/lib/tor, but the tor user can. Read as tor.
                if let Err(e) = compat::become_tor() {
                    eprintln!("error: cannot switch to the tor user: {e}");
                    return 2;
                }
            }
            cli::run(cmd, rest).unwrap_or_else(|| {
                eprintln!("hiddenforge: unknown command {}", py::safe_str(cmd));
                2
            })
        }
    }
}

/// True when root is refused entry to the key directory (EACCES), which is
/// what a container without DAC_OVERRIDE sees.
fn root_cannot_reach_keys() -> bool {
    let keys = std::env::var("HIDDENFORGE_KEYS_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/var/lib/tor/hidden_service".into());
    matches!(fsops::lstat(&keys), Err(e) if e.errno == Some(libc::EACCES))
}

fn python(args: &[String]) -> i32 {
    match args.split_first() {
        Some((script, rest)) if script == "/usr/local/bin/healthcheck.py" => healthcheck(rest),
        Some((script, rest)) if script == "/usr/local/bin/vanity.py" => {
            cli::run("vanity", rest).unwrap_or(2)
        }
        Some((script, rest)) if script == "/usr/local/bin/entrypoint.py" => entrypoint(rest),
        _ => {
            eprintln!(
                "python3: HiddenForge 3.0 has no Python in the image; this form is not one it answers: {}",
                py::safe_str(&args.join(" "))
            );
            127
        }
    }
}

/// Dispatch by program name (also used by the su-exec form).
fn by_name(name: &str, args: &[String]) -> i32 {
    match name {
        "hiddenforge" | "hiddenforge-upload-watch" => hiddenforge(args),
        "healthcheck.py" => healthcheck(args),
        "vanity.py" => cli::run("vanity", args).unwrap_or(2),
        "python3" | "python" | "python3.12" => python(args),
        "cat" => compat::cat(args),
        "sh" => compat::sh(args),
        "test" => compat::test(args),
        "true" => 0,
        "su-exec" => compat::su_exec(args, &by_name),
        "entrypoint.py" | "entrypoint" => entrypoint(args),
        other => {
            // Never boot a second supervisor under an unexpected name.
            eprintln!(
                "hiddenforge: started under an unknown name {}; nothing to do",
                py::safe_str(other)
            );
            2
        }
    }
}

/// The image ENTRYPOINT: an operator subcommand, or boot (unknown args boot,
/// as in 2.x, so a stray argument from an engine never bricks the container).
fn entrypoint(args: &[String]) -> i32 {
    if let Some((cmd, rest)) = args.split_first() {
        if SUBCOMMANDS.contains(&cmd.as_str()) {
            if AS_TOR.contains(&cmd.as_str()) && privs::is_root() {
                if let Err(e) = compat::become_tor() {
                    eprintln!("error: cannot switch to the tor user: {e}");
                    return 2;
                }
            }
            // In the container doctor is always keys-only; cmd_doctor checks nothing else.
            return cli::run(cmd, rest).unwrap_or(2);
        }
    }
    supervisor::run()
}

/// No process of ours ever writes a core file or can be ptrace-attached by a
/// same-uid process: a crash must not put key material on disk.
fn no_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain setrlimit/prctl with valid arguments; failures are harmless.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

fn main() {
    no_dumps();
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or("").to_string())
        .unwrap_or_default();
    let rest = &args[args.len().min(1)..];
    let code = if argv0 == health::GUARDS_ARGV0 {
        guards::main(rest)
    } else {
        by_name(&argv0, rest)
    };
    std::process::exit(code);
}
