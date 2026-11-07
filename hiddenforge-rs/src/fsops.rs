//! Key-volume and DataDirectory operations, ported from entrypoint.py.
//!
//! The key volume is untrusted (restored from a backup, written by another host
//! user, tampered). Every operation here refuses to follow symlinks, holds one
//! descriptor from check to change, and refuses hard links, exactly as 2.x did.

use crate::py;
use std::ffi::CString;
use std::fmt;

/// An error carrying the text CPython's `str(exception)` would show.
#[derive(Debug, Clone, PartialEq)]
pub struct PyErr {
    pub errno: Option<i32>,
    pub msg: String,
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl PyErr {
    /// OSError raised by a call that names a path (os.open, os.lstat, mkdir).
    pub fn os_path(errno: i32, path: &str) -> PyErr {
        PyErr { errno: Some(errno), msg: py::oserror_path(errno, path) }
    }
    /// OSError raised by a descriptor call (fchown, fchmod, fstat).
    pub fn os(errno: i32) -> PyErr {
        PyErr { errno: Some(errno), msg: py::oserror(errno) }
    }
    pub fn runtime(msg: String) -> PyErr {
        PyErr { errno: None, msg }
    }
    pub fn is_permission(&self) -> bool {
        matches!(self.errno, Some(libc::EACCES | libc::EPERM))
    }
}

pub type R<T> = Result<T, PyErr>;

fn cpath(path: &str) -> CString {
    CString::new(path).unwrap_or_else(|_| CString::new("\u{1}").unwrap_or_default())
}

pub struct Fd(pub i32);
impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: closing a descriptor this struct owns.
        unsafe { libc::close(self.0) };
    }
}

pub fn open(path: &str, flags: i32, mode: u32) -> R<Fd> {
    let c = cpath(path);
    // SAFETY: valid C string; mode is used only with O_CREAT.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) };
    if fd < 0 {
        Err(PyErr::os_path(py::last_errno(), path))
    } else {
        Ok(Fd(fd))
    }
}

pub fn fstat(fd: &Fd) -> R<libc::stat> {
    // SAFETY: zeroed stat is valid storage for fstat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fd is open; st is valid.
    if unsafe { libc::fstat(fd.0, &mut st) } != 0 {
        return Err(PyErr::os(py::last_errno()));
    }
    Ok(st)
}

pub fn lstat(path: &str) -> R<libc::stat> {
    let c = cpath(path);
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid C string and storage.
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return Err(PyErr::os_path(py::last_errno(), path));
    }
    Ok(st)
}

pub fn is_type(st: &libc::stat, t: libc::mode_t) -> bool {
    st.st_mode & libc::S_IFMT == t
}

pub fn imode(st: &libc::stat) -> u32 {
    st.st_mode & 0o7777
}

fn lchown(path: &str, uid: u32, gid: u32) -> R<()> {
    let c = cpath(path);
    // SAFETY: valid C string.
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
        return Err(PyErr::os_path(py::last_errno(), path));
    }
    Ok(())
}

fn fchown(fd: &Fd, uid: u32, gid: u32) -> R<()> {
    // SAFETY: fd is open.
    if unsafe { libc::fchown(fd.0, uid, gid) } != 0 {
        return Err(PyErr::os(py::last_errno()));
    }
    Ok(())
}

pub fn fchmod(fd: &Fd, mode: u32) -> R<()> {
    // SAFETY: fd is open.
    if unsafe { libc::fchmod(fd.0, mode as libc::mode_t) } != 0 {
        return Err(PyErr::os(py::last_errno()));
    }
    Ok(())
}

/// Open a directory, refusing a final-component symlink (O_DIRECTORY|O_NOFOLLOW).
pub fn open_dir_nofollow(path: &str) -> R<Fd> {
    open(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0)
}

/// chmod a directory through an O_NOFOLLOW descriptor; optionally only when root owns it.
pub fn chmod_dir_nofollow(path: &str, mode: u32, only_if_root_owned: bool) -> R<bool> {
    let fd = open_dir_nofollow(path)?;
    if only_if_root_owned && fstat(&fd)?.st_uid != 0 {
        return Ok(false);
    }
    fchmod(&fd, mode)?;
    Ok(true)
}

/// _chown_one: lchown a symlink; refuse devices/sockets and hard links; fchown the rest.
pub fn chown_one(path: &str, uid: u32, gid: u32, log: &mut Vec<String>) -> R<()> {
    let st = lstat(path)?;
    if is_type(&st, libc::S_IFLNK) {
        return lchown(path, uid, gid);
    }
    if is_type(&st, libc::S_IFCHR) || is_type(&st, libc::S_IFBLK) || is_type(&st, libc::S_IFSOCK) {
        log.push(format!(
            "Warning: not taking ownership of {} in the key volume: it is a device node or socket, which does not belong there.",
            py::safe_str(path)
        ));
        return Ok(());
    }
    let fd = open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)?;
    let st = fstat(&fd)?;
    if !is_type(&st, libc::S_IFDIR) && st.st_nlink > 1 {
        log.push(format!(
            "Warning: not taking ownership of {}: it has {} hard links, so it is also a file outside this directory. \
             Tor never hard-links its key files; remove the extra links.",
            py::safe_str(path),
            st.st_nlink
        ));
        return Ok(());
    }
    fchown(&fd, uid, gid)
}

fn list_dir(path: &str) -> Option<Vec<(String, bool)>> {
    let rd = std::fs::read_dir(path).ok()?;
    let mut out = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // file_type() is lstat-based: a symlink to a directory is not a directory.
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        out.push((name, is_dir));
    }
    Some(out)
}

/// _chown_r: lchown the root, then every entry below it, never following links.
pub fn chown_r(path: &str, uid: u32, gid: u32, log: &mut Vec<String>) -> R<()> {
    lchown(path, uid, gid)?;
    let mut stack = vec![path.to_string()];
    while let Some(dir) = stack.pop() {
        // os.walk ignores directories it cannot list (onerror=None).
        let Some(entries) = list_dir(&dir) else { continue };
        let (dirs, files): (Vec<_>, Vec<_>) = entries.into_iter().partition(|(_, d)| *d);
        for (name, _) in dirs.iter().chain(files.iter()) {
            chown_one(&format!("{dir}/{name}"), uid, gid, log)?;
        }
        for (name, _) in dirs.iter().rev() {
            stack.push(format!("{dir}/{name}"));
        }
    }
    Ok(())
}

/// _secure_service_dir: make it exactly 0700, or explain why that is impossible.
pub fn secure_service_dir(path: &str) -> R<()> {
    let fd = open_dir_nofollow(path)?;
    let st = fstat(&fd)?;
    let mode = imode(&st);
    if mode == 0o700 {
        return Ok(());
    }
    match fchmod(&fd, 0o700) {
        Ok(()) => Ok(()),
        Err(e) if e.is_permission() => Err(PyErr {
            errno: Some(libc::EPERM),
            msg: format!(
                "[Errno 1] {path} is mode 0o{mode:o}, which Tor refuses, and it cannot be set to 0700 here (it belongs \
                 to uid {} and the runtime grants no FOWNER). Run `chmod 700` on it on the host.",
                st.st_uid
            ),
        }),
        Err(e) => Err(e),
    }
}

fn mkdir_p(path: &str) -> R<()> {
    let mut cur = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        let c = cpath(&cur);
        // SAFETY: valid C string.
        if unsafe { libc::mkdir(c.as_ptr(), 0o777) } != 0 {
            let e = py::last_errno();
            if e == libc::EEXIST {
                // Path.mkdir(exist_ok=True) accepts an existing directory, or a
                // symlink to one; anything else is FileExistsError.
                // SAFETY: as in lstat.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: stat (following) is what pathlib uses here.
                if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 && is_type(&st, libc::S_IFDIR) {
                    continue;
                }
                return Err(PyErr::os_path(libc::EEXIST, &cur));
            }
            return Err(PyErr::os_path(e, &cur));
        }
    }
    Ok(())
}

/// _prepare_hs_dir: create, refuse links/non-dirs, chmod 0700 first, then chown.
pub fn prepare_hs_dir(hs_dir: &str, uid: u32, gid: u32, log: &mut Vec<String>) -> R<()> {
    match lstat(hs_dir) {
        Ok(st) if !is_type(&st, libc::S_IFDIR) => {
            let kind = if is_type(&st, libc::S_IFLNK) { "a symlink" } else { "not a directory" };
            return Err(PyErr::runtime(format!(
                "{hs_dir} in the key volume is {kind}; refusing to use it as a service directory. Replace it with the \
                 real directory (restore it from a backup)."
            )));
        }
        Ok(_) => {}
        Err(e) if e.errno == Some(libc::ENOENT) => {}
        Err(e) => return Err(e),
    }
    mkdir_p(hs_dir)?;
    let r = secure_service_dir(hs_dir).and_then(|()| chown_r(hs_dir, uid, gid, log));
    match r {
        Ok(()) => Ok(()),
        Err(e) if e.is_permission() => {
            let st = lstat(hs_dir)?;
            if !(is_type(&st, libc::S_IFDIR) && st.st_uid == uid && imode(&st) & 0o077 == 0) {
                return Err(e);
            }
            log.push(format!(
                "{} is already the tor user's (prepared by a previous start); nothing to change.",
                py::safe_str(hs_dir)
            ));
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn write_all(fd: &Fd, data: &[u8]) -> R<()> {
    let mut off = 0;
    while off < data.len() {
        // SAFETY: writing from a live slice to an open descriptor.
        let n = unsafe { libc::write(fd.0, data[off..].as_ptr().cast(), data.len() - off) };
        if n < 0 {
            let e = py::last_errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(PyErr::os(e));
        }
        off += n as usize;
    }
    Ok(())
}

/// Write a file through O_NOFOLLOW|O_TRUNC, then fchmod/fchown that descriptor.
pub fn write_nofollow(path: &str, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> R<()> {
    let fd = open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW, mode)?;
    write_all(&fd, data)?;
    fchmod(&fd, mode)?;
    if let Some((u, g)) = owner {
        fchown(&fd, u, g)?;
    }
    Ok(())
}

/// _write_dropped_mappings.
pub fn write_dropped_mappings(path: &str, reasons: &[String], uid: u32, gid: u32, log: &mut Vec<String>) {
    if reasons.is_empty() {
        let c = cpath(path);
        // SAFETY: valid C string.
        if unsafe { libc::unlink(c.as_ptr()) } != 0 {
            let e = py::last_errno();
            if e != libc::ENOENT {
                log.push(format!("Warning: could not remove {path}: {}", py::oserror_path(e, path)));
            }
        }
        return;
    }
    let body = reasons.join("\n") + "\n";
    match write_nofollow(path, body.as_bytes(), 0o600, Some((uid, gid))) {
        Ok(()) => log.push(format!("Recorded {} dropped mapping(s) in {path}", reasons.len())),
        Err(e) => log.push(format!("Warning: could not write {path}: {e}")),
    }
}

pub const ADDRESS_FILE_MAX: usize = 256;

/// _read_small_regular_file: no-follow, non-blocking, regular files only, capped.
pub fn read_small_regular_file(path: &str, max_bytes: usize) -> R<Vec<u8>> {
    let fd = open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0)?;
    if !is_type(&fstat(&fd)?, libc::S_IFREG) {
        return Err(PyErr { errno: Some(libc::EINVAL), msg: format!("[Errno 22] {path} is not a regular file") });
    }
    let mut buf = vec![0u8; max_bytes + 1];
    let mut got = 0;
    while got < buf.len() {
        // SAFETY: reading into the unfilled tail of a live buffer.
        let n = unsafe { libc::read(fd.0, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
        if n < 0 {
            let e = py::last_errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(PyErr::os(e));
        }
        if n == 0 {
            break;
        }
        got += n as usize;
        // os.read() returns after ONE read; a regular file returns all it has.
        break;
    }
    buf.truncate(got);
    if buf.len() > max_bytes {
        return Err(PyErr {
            errno: Some(libc::EFBIG),
            msg: format!("[Errno 27] {path} is larger than {max_bytes} bytes"),
        });
    }
    Ok(buf)
}

pub fn is_onion(s: &str) -> bool {
    s.len() == 62 && s.ends_with(".onion") && s[..56].bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

pub fn is_label(s: &str) -> bool {
    s.len() == 56 && s.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn ascii_strip(data: &[u8]) -> Option<String> {
    if !data.is_ascii() {
        return None;
    }
    Some(py::strip_str(std::str::from_utf8(data).ok()?).to_string())
}

fn random_hex8() -> String {
    let mut b = [0u8; 8];
    // SAFETY: getrandom fills the buffer; 8 bytes never short-reads.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != 8 {
        // A fresh name is required, not a secret: fall back to pid+time.
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        return format!("{:016x}", (t as u64) ^ u64::from(std::process::id()));
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Remembers which publication failures were already reported.
#[derive(Default)]
pub struct PublishState {
    warned: Vec<(String, String, i32)>,
}

impl PublishState {
    fn warn_once(&mut self, name: &str, action: &str, e: &PyErr, keys_root: &str, log: &mut Vec<String>) {
        let errno = e.errno.unwrap_or(0);
        if errno == libc::ENOENT {
            return;
        }
        let key = (name.to_string(), action.split(' ').next().unwrap_or("").to_string(), errno);
        if self.warned.contains(&key) {
            return;
        }
        self.warned.push(key);
        log.push(format!(
            "Warning: cannot publish the .onion address for {name}: {action} failed: {}. The service itself is \
             unaffected -- read the address with 'su-exec tor cat {keys_root}/{name}/hostname' instead. (Reported \
             once; further identical failures are not repeated.)",
            py::strerror(errno)
        ));
    }
}

/// _publish_addresses: copy each valid hostname to <keys_root>/<name>.onion, atomically,
/// once the gate says the service is reachable.
pub fn publish_addresses(
    hs_dirs: &[String],
    keys_root: &str,
    gate: &mut dyn FnMut() -> bool,
    state: &mut PublishState,
    log: &mut Vec<String>,
) {
    let mut pending = Vec::new();
    for hs_dir in hs_dirs {
        let name = hs_dir.rsplit('/').next().unwrap_or(hs_dir).to_string();
        let raw = match read_small_regular_file(&format!("{hs_dir}/hostname"), ADDRESS_FILE_MAX) {
            Ok(r) => r,
            Err(e) => {
                state.warn_once(&name, "read hostname", &e, keys_root, log);
                continue;
            }
        };
        let Some(onion) = ascii_strip(&raw) else { continue };
        if !is_onion(&onion) {
            continue;
        }
        let target = format!("{keys_root}/{name}.onion");
        if let Ok(cur) = read_small_regular_file(&target, ADDRESS_FILE_MAX) {
            if ascii_strip(&cur).as_deref() == Some(onion.as_str()) {
                continue;
            }
        }
        pending.push((name, onion, target));
    }
    if pending.is_empty() || !gate() {
        return;
    }
    for (name, onion, target) in pending {
        let tmp = format!("{keys_root}/.{name}.onion.{}.tmp", random_hex8());
        let mut created = false;
        let r = (|| -> R<()> {
            let fd = open(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o644)?;
            created = true;
            write_all(&fd, format!("{onion}\n").as_bytes())?;
            fchmod(&fd, 0o644)?;
            drop(fd);
            let (a, b) = (cpath(&tmp), cpath(&target));
            // SAFETY: valid C strings.
            if unsafe { libc::rename(a.as_ptr(), b.as_ptr()) } != 0 {
                let e = py::last_errno();
                return Err(PyErr { errno: Some(e), msg: format!("[Errno {e}] {}: {} -> {}", py::strerror(e), py::py_repr(&tmp), py::py_repr(&target)) });
            }
            Ok(())
        })();
        if let Err(e) = r {
            if created {
                let c = cpath(&tmp);
                // SAFETY: valid C string; failure is ignored as in 2.x.
                unsafe { libc::unlink(c.as_ptr()) };
            }
            state.warn_once(&name, &format!("write {target}"), &e, keys_root, log);
            continue;
        }
        log.push(format!("Published address for {name}: {onion}"));
    }
}

/// uid/gid of a user from /etc/passwd (pwd.getpwnam without NSS).
pub fn getpwnam(name: &str) -> Option<(u32, u32, String)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?, f[5].to_string())))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("hf-fsops-{tag}-{}", random_hex8()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn symlinked_service_dir_is_refused() {
        let d = tmpdir("link");
        std::fs::create_dir(format!("{d}/real")).unwrap();
        symlink(format!("{d}/real"), format!("{d}/svc")).unwrap();
        let mut log = vec![];
        let e = prepare_hs_dir(&format!("{d}/svc"), 1000, 1000, &mut log).unwrap_err();
        assert!(e.msg.contains("is a symlink; refusing"));
    }

    #[test]
    fn service_dir_becomes_0700() {
        let d = tmpdir("mode");
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        std::fs::set_permissions(&svc, std::fs::Permissions::from_mode(0o775)).unwrap();
        // SAFETY: getuid/getgid have no preconditions.
        let (u, g) = unsafe { (libc::getuid(), libc::getgid()) };
        prepare_hs_dir(&svc, u, g, &mut vec![]).unwrap();
        assert_eq!(std::fs::metadata(&svc).unwrap().permissions().mode() & 0o7777, 0o700);
    }

    #[test]
    fn hardlink_is_not_chowned_and_is_named() {
        let d = tmpdir("hl");
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        std::fs::write(format!("{d}/outside"), b"x").unwrap();
        std::fs::hard_link(format!("{d}/outside"), format!("{svc}/hs_ed25519_secret_key")).unwrap();
        let mut log = vec![];
        // SAFETY: as above.
        let (u, g) = unsafe { (libc::getuid(), libc::getgid()) };
        chown_r(&svc, u, g, &mut log).unwrap();
        assert!(log.iter().any(|l| l.contains("2 hard links")));
    }

    #[test]
    fn fifo_hostname_does_not_block_and_publish_is_atomic() {
        let d = tmpdir("pub");
        let svc = format!("{d}/a");
        std::fs::create_dir(&svc).unwrap();
        let c = cpath(&format!("{svc}/hostname"));
        // SAFETY: valid C string.
        unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        let mut st = PublishState::default();
        let mut log = vec![];
        publish_addresses(&[svc.clone()], &d, &mut || true, &mut st, &mut log);
        assert!(log.iter().any(|l| l.contains("read hostname failed")));
        std::fs::remove_file(format!("{svc}/hostname")).unwrap();
        let onion = format!("{}.onion", "a".repeat(56));
        std::fs::write(format!("{svc}/hostname"), format!("{onion}\n")).unwrap();
        let mut log = vec![];
        publish_addresses(&[svc.clone()], &d, &mut || false, &mut st, &mut log);
        assert!(std::fs::metadata(format!("{d}/a.onion")).is_err(), "gate said no");
        publish_addresses(&[svc], &d, &mut || true, &mut st, &mut log);
        assert_eq!(std::fs::read_to_string(format!("{d}/a.onion")).unwrap(), format!("{onion}\n"));
        assert_eq!(std::fs::metadata(format!("{d}/a.onion")).unwrap().permissions().mode() & 0o777, 0o644);
    }

    #[test]
    fn onion_regex() {
        assert!(is_onion(&format!("{}.onion", "a2".repeat(28))));
        assert!(!is_onion(&format!("{}.onion", "a1".repeat(28))));
    }
}
