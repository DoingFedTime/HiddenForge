//! Tor's state file, kept across restarts.
//!
//! The DataDirectory is a tmpfs, so Tor's `state` file, where it records the
//! entry guards it has chosen, used to vanish at every container restart, and
//! Tor chose new guards each time. Guards are meant to last for months: each
//! new choice is another chance of picking a hostile relay, and HiddenForge
//! restarts itself on purpose (a moved backend, Tor exiting, a host reboot),
//! so anything that can cause a restart could force a new choice. The state
//! file is now copied to the key volume, into the first service's directory
//! (owned by the tor user, like the keys), and restored before Tor starts.
//!
//! Run as the tor user (`hiddenforge __tor-state load|save <service>`): the
//! DataDirectory and the service directories are the tor user's 0700.

use crate::fsops;
use crate::sealed;

/// Tor's state file in the DataDirectory.
pub const DATA_STATE: &str = "/var/lib/tor/state";
/// Its copy in a service's key directory.
pub const SAVED_NAME: &str = "tor-state";
const KEYS: &str = "/var/lib/tor/hidden_service";
/// Tor's state file is a few kilobytes; anything far larger is not one.
const MAX: usize = 1 << 20;

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A state file Tor wrote: text that starts with Tor's own header line.
fn looks_like_state(data: &[u8]) -> bool {
    data.starts_with(b"# Tor state file")
}

/// Copy `from` to `dir/name` (0600) if it exists and looks like Tor's state.
/// `Ok(false)` when there is nothing to copy.
fn copy(from: &str, dir: &str, name: &str) -> Result<bool, String> {
    let data = match fsops::read_small_regular_file(from, MAX) {
        Ok(d) => d,
        Err(e) if e.errno == Some(libc::ENOENT) => return Ok(false),
        Err(e) => return Err(format!("cannot read {from}: {}", e.msg)),
    };
    if !looks_like_state(&data) {
        return Err(format!("{from} is not a Tor state file; not copied"));
    }
    sealed::write_atomic(dir, name, &data, 0o600)?;
    Ok(true)
}

/// `load`: the saved copy into the DataDirectory (before Tor starts).
/// `save`: the DataDirectory's state into the key volume.
pub fn helper(op: &str, name: &str) -> i32 {
    helper_at(KEYS, DATA_STATE, op, name)
}

fn helper_at(keys: &str, data_state: &str, op: &str, name: &str) -> i32 {
    if !valid_name(name) {
        return 2;
    }
    let saved = format!("{keys}/{name}/{SAVED_NAME}");
    let (data_dir, data_name) = data_state.rsplit_once('/').unwrap_or((".", data_state));
    let r = match op {
        "load" => copy(&saved, data_dir, data_name),
        "save" => copy(data_state, &format!("{keys}/{name}"), SAVED_NAME),
        _ => return 2,
    };
    match r {
        Ok(true) => 0,
        Ok(false) => 3,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(String);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let d = std::env::temp_dir()
                .join(format!("hf-torstate-{tag}-{}", std::process::id()))
                .to_string_lossy()
                .into_owned();
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(format!("{d}/keys/app")).unwrap();
            std::fs::create_dir_all(format!("{d}/data")).unwrap();
            Tmp(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const STATE: &[u8] =
        b"# Tor state file last generated on 2026-11-17\nGuard in=default rsa_id=AAAA\n";

    fn mode(p: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn save_then_load_round_trips_the_guards() {
        let t = Tmp::new("rt");
        let (keys, data) = (format!("{}/keys", t.0), format!("{}/data/state", t.0));
        std::fs::write(&data, STATE).unwrap();
        assert_eq!(helper_at(&keys, &data, "save", "app"), 0);
        let saved = format!("{keys}/app/{SAVED_NAME}");
        assert_eq!(std::fs::read(&saved).unwrap(), STATE);
        assert_eq!(mode(&saved), 0o600);
        std::fs::remove_file(&data).unwrap();
        assert_eq!(helper_at(&keys, &data, "load", "app"), 0);
        assert_eq!(std::fs::read(&data).unwrap(), STATE);
        assert_eq!(mode(&data), 0o600);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn nothing_to_copy_is_not_an_error() {
        let t = Tmp::new("none");
        let (keys, data) = (format!("{}/keys", t.0), format!("{}/data/state", t.0));
        assert_eq!(helper_at(&keys, &data, "load", "app"), 3, "first start");
        assert_eq!(
            helper_at(&keys, &data, "save", "app"),
            3,
            "Tor wrote nothing yet"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_file_that_is_not_tor_state_or_is_a_link_is_never_copied() {
        let t = Tmp::new("bad");
        let (keys, data) = (format!("{}/keys", t.0), format!("{}/data/state", t.0));
        let saved = format!("{keys}/app/{SAVED_NAME}");
        std::fs::write(&saved, b"not a state file").unwrap();
        assert_eq!(helper_at(&keys, &data, "load", "app"), 1);
        assert!(std::fs::metadata(&data).is_err(), "nothing written");
        std::fs::remove_file(&saved).unwrap();
        let outside = format!("{}/outside", t.0);
        std::fs::write(&outside, STATE).unwrap();
        std::os::unix::fs::symlink(&outside, &saved).unwrap();
        assert_eq!(helper_at(&keys, &data, "load", "app"), 1, "no-follow");
        assert!(std::fs::metadata(&data).is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_save_never_recreates_a_service_directory_that_was_rotated_away() {
        // `rotate` moves the service directory, and its tor-state, out of the
        // volume; the new address must not inherit the old guards from a save
        // that ran before the restart.
        let t = Tmp::new("rotated");
        let (keys, data) = (format!("{}/keys", t.0), format!("{}/data/state", t.0));
        std::fs::write(&data, STATE).unwrap();
        std::fs::remove_dir(format!("{keys}/app")).unwrap();
        assert_eq!(helper_at(&keys, &data, "save", "app"), 1);
        assert!(
            std::fs::metadata(format!("{keys}/app")).is_err(),
            "nothing recreated"
        );
    }

    #[test]
    fn names_and_operations_are_checked_before_anything_is_touched() {
        for bad in ["", "A", "a/b", "../x", "a.b", "a b"] {
            assert_eq!(
                helper_at("/nonexistent", "/nonexistent/state", "load", bad),
                2
            );
        }
        assert_eq!(
            helper_at("/nonexistent", "/nonexistent/state", "copy", "app"),
            2
        );
    }
}
