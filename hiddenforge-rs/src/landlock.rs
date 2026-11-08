//! Landlock: per-process filesystem and TCP restrictions, applied by this binary
//! itself, so they need nothing from the compose file or the runtime.
//!
//! A ruleset is built in the parent (opening paths, allocating) and only
//! *applied* in the child between fork and exec, where nothing but two system
//! calls run. Kernels or runtimes without Landlock (or a seccomp profile that
//! refuses its system calls) get the 2.x behaviour and one log line saying so;
//! this layer is defence in depth on top of the capability drop, Tor's own
//! sandbox and the runtime's seccomp profile, never a replacement for them.

use std::ffi::CString;

// Filesystem access rights (ABI 1..5).
pub const EXECUTE: u64 = 1 << 0;
pub const WRITE_FILE: u64 = 1 << 1;
pub const READ_FILE: u64 = 1 << 2;
pub const READ_DIR: u64 = 1 << 3;
pub const REMOVE_DIR: u64 = 1 << 4;
pub const REMOVE_FILE: u64 = 1 << 5;
pub const MAKE_DIR: u64 = 1 << 7;
pub const MAKE_REG: u64 = 1 << 8;
pub const MAKE_SOCK: u64 = 1 << 9;
pub const REFER: u64 = 1 << 13; // ABI 2
pub const TRUNCATE: u64 = 1 << 14; // ABI 3
pub const IOCTL_DEV: u64 = 1 << 15; // ABI 5
const NET_BIND_TCP: u64 = 1 << 0; // ABI 4
const NET_CONNECT_TCP: u64 = 1 << 1;

pub const READ: u64 = READ_FILE | READ_DIR;
/// Everything needed to create, replace and remove files in a directory.
pub const RW: u64 = READ
    | WRITE_FILE
    | REMOVE_FILE
    | REMOVE_DIR
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | REFER
    | TRUNCATE;

const SYS_CREATE: libc::c_long = 444;
const SYS_ADD_RULE: libc::c_long = 445;
const SYS_RESTRICT: libc::c_long = 446;
const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// The kernel's Landlock ABI version, or 0 if unavailable.
pub fn abi() -> i64 {
    // SAFETY: the documented ABI probe: NULL attr, size 0, VERSION flag.
    let v = unsafe {
        libc::syscall(
            SYS_CREATE,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if v < 0 {
        0
    } else {
        v
    }
}

fn fs_mask(abi: i64) -> u64 {
    let mut m = (1 << 13) - 1; // ABI 1: bits 0..12
    if abi >= 2 {
        m |= REFER;
    }
    if abi >= 3 {
        m |= TRUNCATE;
    }
    if abi >= 5 {
        m |= IOCTL_DEV;
    }
    m
}

pub struct Ruleset {
    fd: i32,
    pub abi: i64,
}

impl Drop for Ruleset {
    fn drop(&mut self) {
        // SAFETY: closing the ruleset fd we own.
        unsafe { libc::close(self.fd) };
    }
}

/// Build a ruleset that allows exactly `rules` (path, rights) and, when
/// `deny_tcp`, no TCP bind or connect at all. Paths that do not exist are
/// skipped (a rule for them would allow nothing anyway).
pub fn build(rules: &[(&str, u64)], deny_tcp: bool) -> Result<Ruleset, String> {
    let abi = abi();
    if abi < 1 {
        return Err("Landlock is not available in this kernel or runtime".into());
    }
    let handled = fs_mask(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
        handled_access_net: if deny_tcp && abi >= 4 {
            NET_BIND_TCP | NET_CONNECT_TCP
        } else {
            0
        },
    };
    let size = if abi >= 4 {
        std::mem::size_of::<RulesetAttr>()
    } else {
        8
    };
    // SAFETY: attr is a valid ruleset_attr of `size` bytes.
    let fd = unsafe { libc::syscall(SYS_CREATE, &attr as *const RulesetAttr, size, 0u32) };
    if fd < 0 {
        return Err(format!(
            "landlock_create_ruleset: {}",
            crate::py::strerror(crate::py::last_errno())
        ));
    }
    let rs = Ruleset { fd: fd as i32, abi };
    for (path, rights) in rules {
        let Ok(c) = CString::new(*path) else { continue };
        // SAFETY: O_PATH open of a path we name; closed below.
        let pfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if pfd < 0 {
            continue;
        }
        let mut allowed = rights & handled;
        // SAFETY: fstat on our O_PATH fd.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(pfd, &mut st) } == 0 && st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            // Rights that only make sense on directories are refused on files.
            allowed &= EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;
        }
        let pb = PathBeneath {
            allowed_access: allowed,
            parent_fd: pfd,
        };
        // SAFETY: valid ruleset fd and path_beneath attr.
        let r = unsafe {
            libc::syscall(
                SYS_ADD_RULE,
                rs.fd,
                RULE_PATH_BENEATH,
                &pb as *const PathBeneath,
                0u32,
            )
        };
        let err = crate::py::last_errno();
        // SAFETY: closing our O_PATH fd.
        unsafe { libc::close(pfd) };
        if r != 0 {
            return Err(format!(
                "landlock_add_rule {path}: {}",
                crate::py::strerror(err)
            ));
        }
    }
    Ok(rs)
}

/// Enforce the ruleset behind `fd` on the calling thread: two system calls.
///
/// # Safety
/// `fd` must be an open Landlock ruleset descriptor.
pub unsafe fn enforce_fd(fd: i32) -> i32 {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return *libc::__errno_location();
    }
    if libc::syscall(SYS_RESTRICT, fd, 0u32) != 0 {
        return *libc::__errno_location();
    }
    0
}

impl Ruleset {
    /// Enforce on the calling thread (and everything it execs). Only system
    /// calls, no allocation: safe between fork and exec.
    ///
    /// # Safety
    /// Must be called in a process where `self.fd` is still open.
    pub unsafe fn enforce_raw(&self) -> i32 {
        enforce_fd(self.fd)
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub fn enforce(&self) -> Result<(), String> {
        // SAFETY: fd is open (we own it).
        match unsafe { self.enforce_raw() } {
            0 => Ok(()),
            e => Err(format!(
                "landlock_restrict_self: {}",
                crate::py::strerror(e)
            )),
        }
    }
}

/// The supervisor's own domain, which every child inherits. It must cover Tor:
/// Tor makes TCP connections to relays on any port, so TCP is not restricted
/// here; Tor's own seccomp sandbox and the runtime profile still apply to it.
pub fn supervisor_rules() -> Vec<(&'static str, u64)> {
    vec![
        ("/usr/local/bin/hiddenforge", EXECUTE | READ_FILE),
        ("/usr/bin/tor", EXECUTE | READ_FILE),
        ("/lib", READ | EXECUTE),
        ("/usr/lib", READ | EXECUTE),
        ("/etc", READ),
        ("/usr/share/tor", READ),
        ("/usr/share/zoneinfo", READ),
        ("/proc", READ),
        ("/sys/fs/cgroup", READ),
        ("/sys/devices/system/cpu", READ),
        ("/dev/null", READ_FILE | WRITE_FILE),
        ("/dev/urandom", READ_FILE),
        ("/dev/random", READ_FILE),
        ("/var/lib/tor", RW),
    ]
}

/// The guards (bandguards/rendguard) read the consensus file and talk to the
/// control socket; nothing else, and no TCP.
/// The runtime binary links the image's libcrypto: every helper needs the
/// loader and the shared libraries, read-only.
const LIBS: [(&str, u64); 2] = [("/lib", READ | EXECUTE), ("/usr/lib", READ | EXECUTE)];

pub fn guards_rules() -> Vec<(&'static str, u64)> {
    vec![
        LIBS[0],
        LIBS[1],
        ("/usr/local/bin/hiddenforge", EXECUTE | READ_FILE),
        ("/etc/localtime", READ_FILE),
        ("/usr/share/zoneinfo", READ),
        ("/var/lib/tor", READ_FILE | READ_DIR),
    ]
}

/// The upload watcher records addresses in the DataDirectory.
pub fn watcher_rules() -> Vec<(&'static str, u64)> {
    vec![
        LIBS[0],
        LIBS[1],
        ("/usr/local/bin/hiddenforge", EXECUTE | READ_FILE),
        ("/var/lib/tor", RW),
    ]
}

/// The healthcheck and the small helpers read the torrc, the DataDirectory
/// and /proc, and may signal (no file access needed for that).
pub fn reader_rules() -> Vec<(&'static str, u64)> {
    vec![
        LIBS[0],
        LIBS[1],
        ("/usr/local/bin/hiddenforge", EXECUTE | READ_FILE),
        ("/etc/tor", READ),
        ("/etc/passwd", READ_FILE),
        ("/proc", READ),
        ("/var/lib/tor", READ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn denies_outside_and_allows_inside() {
        if abi() < 1 {
            return; // not available on this host
        }
        let d = std::env::temp_dir().join(format!("hf-ll-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("ok"), b"x").unwrap();
        let dp = d.to_string_lossy().into_owned();
        // SAFETY: fork for an isolated child; it only calls async-signal-safe-ish
        // functions we control and exits with a code.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let rs = match build(&[(&dp, READ)], true) {
                Ok(r) => r,
                // SAFETY: _exit(2) in the forked child; no destructors are owed.
                Err(_) => unsafe { libc::_exit(3) },
            };
            if rs.enforce().is_err() {
                // SAFETY: as above.
                unsafe { libc::_exit(4) };
            }
            let inside = std::fs::read(format!("{dp}/ok")).is_ok();
            let outside =
                std::fs::read("/etc/hostname").is_ok() || std::fs::read("/etc/passwd").is_ok();
            let write = std::fs::write(format!("{dp}/new"), b"y").is_ok();
            let tcp = std::net::TcpStream::connect("127.0.0.1:9").is_ok();
            // SAFETY: as above.
            unsafe {
                libc::_exit(if inside && !outside && !write && !tcp {
                    0
                } else {
                    5
                })
            };
        }
        let mut status = 0;
        // SAFETY: waiting for our child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(libc::WEXITSTATUS(status), 0, "landlock child status");
    }
}
