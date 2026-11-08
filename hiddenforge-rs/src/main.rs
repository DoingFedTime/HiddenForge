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
        ("__read-hostname", [p]) if hostname_path_ok(p) => {
            match fsops::read_small_regular_file(p, fsops::ADDRESS_FILE_MAX) {
                Ok(d) => {
                    use std::io::Write;
                    i32::from(std::io::stdout().write_all(&d).is_err())
                }
                Err(_) => 1,
            }
        }
        // Run as the tor user by the supervisor, which holds no CAP_KILL.
        ("__kill", [pid, sig]) => match kill_request(pid, sig) {
            // SAFETY: kill(2); the kernel enforces that we only reach our own processes.
            Some((p, s)) => i32::from(unsafe { libc::kill(p, s) } != 0),
            None => 2,
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

/// The only files `__read-hostname` serves: a hostname file inside the tor
/// volumes, with no way out of them.
fn hostname_path_ok(p: &str) -> bool {
    (p.starts_with("/var/lib/tor/hidden_service/") || p.starts_with("/var/lib/tor/hs-ram/"))
        && p.ends_with("/hostname")
        && !p.contains("/../")
}

/// `__kill <pid> <signal>`: only a real process (never 0, 1 or a group) and only
/// TERM, INT or KILL. Nothing here signals anything; the caller does.
fn kill_request(pid: &str, sig: &str) -> Option<(i32, i32)> {
    let (p, s) = (pid.parse::<i32>().ok()?, sig.parse::<i32>().ok()?);
    (p > 1 && (s == libc::SIGTERM || s == libc::SIGINT || s == libc::SIGKILL)).then_some((p, s))
}

/// The key directory the CLI will use: the variable when set and not empty.
fn keys_dir_from(var: Option<String>) -> String {
    var.filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/var/lib/tor/hidden_service".into())
}

/// True when root is refused entry to the key directory (EACCES), which is
/// what a container without DAC_OVERRIDE sees.
fn root_cannot_reach_keys() -> bool {
    keys_unreachable(&keys_dir_from(std::env::var("HIDDENFORGE_KEYS_DIR").ok()))
}

fn keys_unreachable(keys: &str) -> bool {
    matches!(fsops::lstat(keys), Err(e) if e.errno == Some(libc::EACCES))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that is made traversable again and removed even when a test panics.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("hf-main-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(rd) = std::fs::read_dir(&self.0) {
                for e in rd.flatten() {
                    let _ =
                        std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o700));
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn hostname_files_are_served_only_from_the_tor_volumes() {
        for ok in [
            "/var/lib/tor/hidden_service/a/hostname",
            "/var/lib/tor/hs-ram/a/hostname",
            "/var/lib/tor/hidden_service/a/b/hostname",
            "/var/lib/tor/hs-ram/hostname",
        ] {
            assert!(hostname_path_ok(ok), "{ok}");
        }
        for bad in [
            "/etc/hostname",
            "/var/lib/tor/hidden_service/a/hostnam",
            "/var/lib/tor/hidden_service/a/hostname2",
            "/var/lib/tor/hidden_service/a/xhostname",
            "/var/lib/tor/other/a/hostname",
            "/var/lib/tor/hidden_servic/a/hostname",
            "/var/lib/tor/hidden_service",
            "/var/lib/tor/hidden_service/hostname.d/x",
            "/var/lib/tor/hs-ram",
            "var/lib/tor/hidden_service/a/hostname",
            "hostname",
            "",
            "/var/lib/tor/hidden_service/../../../etc/hostname",
            "/var/lib/tor/hidden_service/a/../../../../etc/hostname",
            "/var/lib/tor/hs-ram/a/../b/hostname",
        ] {
            assert!(!hostname_path_ok(bad), "{bad}");
        }
    }

    #[test]
    fn kill_requests_name_a_real_process_and_one_of_three_signals() {
        let (term, int, kill) = (libc::SIGTERM, libc::SIGINT, libc::SIGKILL);
        for s in [term, int, kill] {
            assert_eq!(kill_request("2", &s.to_string()), Some((2, s)));
            assert_eq!(kill_request("4194304", &s.to_string()), Some((4194304, s)));
        }
        // pid 0 is the caller's process group, -1 is everything, 1 is init, below that are groups.
        for pid in [
            "0",
            "1",
            "-1",
            "-2",
            "-15",
            "",
            "x",
            "1.5",
            "2 ",
            " 2",
            "99999999999999",
        ] {
            assert_eq!(kill_request(pid, "15"), None, "pid {pid:?}");
        }
        for sig in [
            "0", "1", "3", "9 ", "10", "12", "17", "18", "19", "-9", "", "TERM", "15.0",
        ] {
            assert_eq!(kill_request("2", sig), None, "signal {sig:?}");
        }
    }

    #[test]
    fn the_key_directory_default_and_override() {
        assert_eq!(keys_dir_from(None), "/var/lib/tor/hidden_service");
        assert_eq!(
            keys_dir_from(Some(String::new())),
            "/var/lib/tor/hidden_service"
        );
        assert_eq!(keys_dir_from(Some("/srv/k".into())), "/srv/k");
    }

    #[test]
    fn only_a_refused_entry_counts_as_unreachable() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("reach");
        let root = s.0.to_string_lossy().into_owned();
        assert!(!keys_unreachable(&root), "an ordinary directory");
        assert!(
            !keys_unreachable(&format!("{root}/missing")),
            "ENOENT is not EACCES"
        );
        let closed = s.0.join("closed");
        std::fs::create_dir_all(closed.join("keys")).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = keys_unreachable(&format!("{}/keys", closed.display()));
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        if privs::is_root() {
            assert!(!denied, "root passes through a 0000 directory");
        } else {
            assert!(denied, "EACCES on the way in");
        }
    }
}
