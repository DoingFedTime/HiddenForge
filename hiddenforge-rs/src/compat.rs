//! Running as the tor user, and the one command older installs still send.
//!
//! The image has no shell, no Python and no su-exec. Every command HiddenForge
//! ships or documents is `hiddenforge <command>`. One exception is forced by
//! files that live on operators' hosts, not in the image: compose files written
//! by earlier releases declare the healthcheck as
//! `su-exec tor python3 /usr/local/bin/healthcheck.py`, and an image update
//! cannot change a compose file. That single command (with or without
//! `--json`) runs the native healthcheck; anything else under that name is
//! refused.

use crate::fsops;
use crate::privs;
use crate::py;

/// The healthcheck command earlier compose files carry, after `su-exec`.
const LEGACY_HEALTHCHECK: [&str; 3] = ["tor", "python3", "/usr/local/bin/healthcheck.py"];

/// `su-exec tor python3 /usr/local/bin/healthcheck.py [--json]`: the native
/// healthcheck. `Some(json)` for exactly that command, else `None`.
pub fn legacy_healthcheck(argv: &[String]) -> Option<bool> {
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    match a.as_slice() {
        [u, p, s] if [*u, *p, *s] == LEGACY_HEALTHCHECK => Some(false),
        [u, p, s, "--json"] if [*u, *p, *s] == LEGACY_HEALTHCHECK => Some(true),
        _ => None,
    }
}

/// The refusal for any other command under a name the image does not have.
pub fn refuse(name: &str, argv: &[String]) -> i32 {
    eprintln!(
        "{name}: the HiddenForge image has no {name}; this command is not one it runs: {}. Use `hiddenforge <command>` (see `hiddenforge info`).",
        py::safe_str(&argv.join(" "))
    );
    127
}

/// 0 if `path` itself is a Unix socket (lstat: a link to one is not), else 1.
pub fn is_socket(path: &str) -> i32 {
    match fsops::lstat(path) {
        Ok(st) if fsops::is_type(&st, libc::S_IFSOCK) => 0,
        _ => 1,
    }
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

/// Become tor when running as root; a process that is already unprivileged
/// stays as it is.
pub fn become_tor_if_root() -> Result<(), String> {
    if privs::is_root() {
        become_tor()
    } else {
        Ok(())
    }
}

/// The drop to `want` worked only if both ids are now `want` and root can no
/// longer be regained.
fn drop_took_effect(want: u32, uid: u32, euid: u32, regained_root: bool) -> bool {
    uid == want && euid == want && !regained_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn only_the_exact_healthcheck_command_is_recognised() {
        let hc = ["tor", "python3", "/usr/local/bin/healthcheck.py"];
        assert_eq!(legacy_healthcheck(&strs(&hc)), Some(false));
        let mut json = hc.to_vec();
        json.push("--json");
        assert_eq!(legacy_healthcheck(&strs(&json)), Some(true));
        for bad in [
            &[
                "tor",
                "python3",
                "/usr/local/bin/healthcheck.py",
                "--watch-uploads",
            ][..],
            &["tor", "python3", "/usr/local/bin/vanity.py"],
            &["tor", "python3", "-c", "print(1)"],
            &["tor", "cat", "/etc/tor/torrc"],
            &["tor", "sh"],
            &["root", "python3", "/usr/local/bin/healthcheck.py"],
            &["tor", "python3", "healthcheck.py"],
            &["tor", "tor"],
            &[],
        ] {
            assert_eq!(legacy_healthcheck(&strs(bad)), None, "{bad:?}");
        }
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
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn is_socket_is_true_only_for_a_socket_itself() {
        let d = std::env::temp_dir().join(format!("hf-compat-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("dir")).unwrap();
        let p = |n: &str| d.join(n).to_string_lossy().into_owned();
        let _listener = std::os::unix::net::UnixListener::bind(p("control.sock")).unwrap();
        std::fs::write(p("file"), b"x").unwrap();
        std::os::unix::fs::symlink(p("control.sock"), p("link")).unwrap();
        assert_eq!(is_socket(&p("control.sock")), 0);
        assert_eq!(is_socket(&p("file")), 1);
        assert_eq!(is_socket(&p("dir")), 1);
        assert_eq!(is_socket(&p("missing")), 1);
        assert_eq!(
            is_socket(&p("link")),
            1,
            "lstat: a link to a socket is not one"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
