//! 2.x compatibility forms. 3.0 has no shell, no Python, no su-exec and no
//! coreutils, but compose files, deploy scripts, documentation and older
//! hiddenforge CLIs already in use run these exact commands inside the
//! container. Each name below answers ONLY the forms 2.x actually used (mined
//! from every release v2.0.0..v2.1.6) and refuses anything else, so the image
//! gains no general-purpose tool. Every refusal names the 3.0 command.

use crate::fsops;
use crate::privs;
use crate::py;

const KEYS: &str = "/var/lib/tor/hidden_service";

/// The ONE shell script any released CLI ran in the container (2.1.x doctor's
/// _runtime_state). Matched byte for byte; computed natively.
pub const DOCTOR_SCRIPT: &str = "echo \"swap=$(cat /sys/fs/cgroup/memory.swap.max 2>/dev/null)\"; echo \"pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null)\"; echo \"capbnd=$(sed -n \"s/^CapBnd:[[:space:]]*//p\" /proc/1/status)\"; echo \"hostswap=$(tail -n +2 /proc/swaps 2>/dev/null | wc -l)\"";

fn refuse(name: &str, argv: &[String]) -> i32 {
    eprintln!(
        "{name}: HiddenForge 3.0 has no {name} in the image; this form is not one it answers: {}. Use `hiddenforge <command>` (see `hiddenforge info`).",
        py::safe_str(&argv.join(" "))
    );
    127
}

fn read_trimmed(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim_end_matches('\n').to_string())
        .unwrap_or_default()
}

/// `sh -c <the 2.1.x doctor script>`.
pub fn sh(argv: &[String]) -> i32 {
    if argv.len() == 2 && argv[0] == "-c" && argv[1] == DOCTOR_SCRIPT {
        let capbnd = std::fs::read_to_string("/proc/1/status")
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("CapBnd:")
                        .map(|v| v.trim_start().to_string())
                })
            })
            .unwrap_or_default();
        let hostswap = std::fs::read_to_string("/proc/swaps")
            .map(|s| s.lines().skip(1).count())
            .unwrap_or(0);
        println!("swap={}", read_trimmed("/sys/fs/cgroup/memory.swap.max"));
        println!("pids={}", read_trimmed("/sys/fs/cgroup/pids.max"));
        println!("capbnd={capbnd}");
        println!("hostswap={hostswap}");
        return 0;
    }
    refuse("sh", argv)
}

fn cat_allowed(path: &str) -> bool {
    if path == "/etc/tor/torrc" || path == "/var/lib/tor/dropped-mappings" {
        return true;
    }
    if let Some(rest) = path.strip_prefix(&format!("{KEYS}/")) {
        if let Some(name) = rest.strip_suffix("/hostname") {
            return !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        }
    }
    false
}

/// `cat <hostname | torrc | dropped-mappings>`: no-follow, regular files, capped.
pub fn cat(argv: &[String]) -> i32 {
    if argv.len() != 1 || !cat_allowed(&argv[0]) {
        return refuse("cat", argv);
    }
    match fsops::read_small_regular_file(&argv[0], 1 << 20) {
        Ok(data) => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&data);
            0
        }
        Err(e) => {
            eprintln!(
                "cat: {}: {}",
                argv[0],
                py::strerror(e.errno.unwrap_or(libc::EIO))
            );
            1
        }
    }
}

/// `test -S <path>` (the 2.x control-socket probe).
pub fn test(argv: &[String]) -> i32 {
    if argv.len() == 2 && argv[0] == "-S" {
        return match fsops::lstat(&argv[1]) {
            Ok(st) if fsops::is_type(&st, libc::S_IFSOCK) => 0,
            _ => 1,
        };
    }
    refuse("test", argv)
}

/// Drop to the tor user in this process (setgroups, setgid, setuid), and check it.
pub fn become_tor() -> Result<(), String> {
    let Some((uid, gid, home)) = fsops::getpwnam("tor") else {
        return Err("there is no tor user in /etc/passwd".into());
    };
    // SAFETY: plain credential syscalls; each result is checked.
    unsafe {
        if libc::geteuid() == uid {
            return Ok(());
        }
        let groups = [gid];
        if libc::setgroups(1, groups.as_ptr()) != 0 {
            return Err(format!("setgroups: {}", py::strerror(py::last_errno())));
        }
        if libc::setgid(gid) != 0 {
            return Err(format!("setgid({gid}): {}", py::strerror(py::last_errno())));
        }
        if libc::setuid(uid) != 0 {
            return Err(format!("setuid({uid}): {}", py::strerror(py::last_errno())));
        }
        if !drop_took_effect(uid, libc::getuid(), libc::geteuid(), libc::setuid(0) == 0) {
            return Err("privilege drop did not take effect".into());
        }
    }
    std::env::set_var(
        "HOME",
        if home.is_empty() {
            "/var/lib/tor"
        } else {
            &home
        },
    );
    Ok(())
}

/// The drop to `want` worked only if both ids are now `want` and root can no
/// longer be regained.
fn drop_took_effect(want: u32, uid: u32, euid: u32, regained_root: bool) -> bool {
    uid == want && euid == want && !regained_root
}

/// `su-exec tor <argv...>`: become tor, then answer the allowed forms.
pub fn su_exec(argv: &[String], dispatch: &dyn Fn(&str, &[String]) -> i32) -> i32 {
    let Some((user, rest)) = argv.split_first() else {
        eprintln!("Usage: su-exec user-spec command [args]");
        return 1;
    };
    if !matches!(user.as_str(), "tor" | "tor:tor" | "100" | "100:101") {
        return refuse("su-exec", argv);
    }
    if rest.is_empty() {
        eprintln!("Usage: su-exec user-spec command [args]");
        return 1;
    }
    if privs::is_root() {
        if let Err(e) = become_tor() {
            eprintln!("su-exec: {e}");
            return 1;
        }
    }
    let prog = rest[0].rsplit('/').next().unwrap_or("").to_string();
    match prog.as_str() {
        "true" | "test" | "cat" | "python3" | "python" | "hiddenforge" | "healthcheck.py"
        | "vanity.py" => dispatch(&prog, &rest[1..]),
        "tor" => exec_tor(&rest[1..]),
        _ => refuse("su-exec", argv),
    }
}

/// Replace this process with the real Tor.
pub fn exec_tor(args: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;
    let e = std::process::Command::new("/usr/bin/tor")
        .arg0("tor")
        .args(args)
        .exec();
    eprintln!("su-exec: tor: {e}");
    127
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cat_allowlist() {
        assert!(cat_allowed("/var/lib/tor/hidden_service/myapp/hostname"));
        assert!(cat_allowed("/etc/tor/torrc"));
        assert!(!cat_allowed(
            "/var/lib/tor/hidden_service/myapp/hs_ed25519_secret_key"
        ));
        assert!(!cat_allowed("/var/lib/tor/hidden_service/../x/hostname"));
        assert!(!cat_allowed("/etc/shadow"));
    }

    #[test]
    fn sh_refuses_everything_else() {
        assert_eq!(sh(&[]), 127);
        assert_eq!(sh(&["-c".into()]), 127);
        assert_eq!(sh(&["-x".into(), DOCTOR_SCRIPT.into()]), 127);
    }

    #[test]
    fn cat_refuses_the_secret_key_and_extra_arguments() {
        // The allowlist is what keeps `cat` from printing a key; test the
        // command, not only the predicate.
        let secret = "/var/lib/tor/hidden_service/myapp/hs_ed25519_secret_key".to_string();
        assert_eq!(
            cat(std::slice::from_ref(&secret)),
            127,
            "the secret key is refused"
        );
        assert_eq!(cat(&["/etc/shadow".into()]), 127);
        assert_eq!(cat(&[]), 127);
        let host = "/var/lib/tor/hidden_service/nosuchservice/hostname".to_string();
        assert_eq!(
            cat(&[host.clone(), secret]),
            127,
            "two paths are refused even if one is allowed"
        );
        assert_eq!(
            cat(&[host]),
            1,
            "an allowed path that does not exist is an error, not a refusal"
        );
    }

    #[test]
    fn test_answers_only_dash_s() {
        assert_eq!(test(&["-S".into(), "/definitely/not/a/socket".into()]), 1);
        assert_eq!(test(&["-f".into(), "/etc/passwd".into()]), 127);
        assert_eq!(test(&["-S".into()]), 127);
    }

    #[test]
    fn a_drop_counts_only_when_complete() {
        assert!(drop_took_effect(100, 100, 100, false));
        assert!(!drop_took_effect(100, 0, 100, false), "real uid still root");
        assert!(
            !drop_took_effect(100, 100, 0, false),
            "effective uid still root"
        );
        assert!(
            !drop_took_effect(100, 100, 100, true),
            "root could be regained"
        );
        assert!(
            !drop_took_effect(100, 101, 101, false),
            "dropped to the wrong user"
        );
    }

    #[test]
    fn su_exec_only_becomes_tor() {
        let d = |_: &str, _: &[String]| 0;
        assert_eq!(su_exec(&["root".into(), "true".into()], &d), 127);
        assert_eq!(su_exec(&[], &d), 1);
        assert_eq!(su_exec(&["tor".into()], &d), 1);
        assert_eq!(su_exec(&["tor".into(), "/bin/bash".into()], &d), 127);
        assert_eq!(sh(&["-c".into(), "id".into()]), 127);
        assert_eq!(sh(&["-c".into(), format!("{DOCTOR_SCRIPT} ")]), 127);
    }
}
