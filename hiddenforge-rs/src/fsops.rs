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
        PyErr {
            errno: Some(errno),
            msg: py::oserror_path(errno, path),
        }
    }
    /// OSError raised by a descriptor call (fchown, fchmod, fstat).
    pub fn os(errno: i32) -> PyErr {
        PyErr {
            errno: Some(errno),
            msg: py::oserror(errno),
        }
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
    open(
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
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
    let fd = open(
        path,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )?;
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
        let Some(entries) = list_dir(&dir) else {
            continue;
        };
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

/// Each ancestor of `path` and then `path`, the order Path.mkdir(parents=True)
/// creates them. A relative path stays relative to the working directory.
fn mkdir_p_steps(path: &str) -> Vec<String> {
    let mut cur = String::from(if path.starts_with('/') { "/" } else { "" });
    let mut out = Vec::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        if !cur.is_empty() && !cur.ends_with('/') {
            cur.push('/');
        }
        cur.push_str(part);
        out.push(cur.clone());
    }
    out
}

fn mkdir_p(path: &str) -> R<()> {
    for cur in mkdir_p_steps(path) {
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

/// mkdir (mode 0700) if missing, refuse anything that is not a real directory,
/// then hand it to `uid:gid` through an O_NOFOLLOW descriptor.
pub fn mkdir_owned(path: &str, uid: u32, gid: u32) -> R<()> {
    match lstat(path) {
        Ok(st) if !is_type(&st, libc::S_IFDIR) => {
            return Err(PyErr::runtime(format!(
                "{path} is not a directory; refusing to use it"
            )));
        }
        Ok(_) => {}
        Err(e) if e.errno == Some(libc::ENOENT) => {
            let c = cpath(path);
            // SAFETY: valid C string.
            if unsafe { libc::mkdir(c.as_ptr(), 0o700) } != 0 {
                return Err(PyErr::os_path(py::last_errno(), path));
            }
        }
        Err(e) => return Err(e),
    }
    let fd = open_dir_nofollow(path)?;
    fchmod(&fd, 0o700)?;
    // SAFETY: fd is open; chown may be a no-op (same owner) in no-root mode.
    unsafe { libc::fchown(fd.0, uid, gid) };
    Ok(())
}

/// _prepare_hs_dir: create, refuse links/non-dirs, chmod 0700 first, then chown.
pub fn prepare_hs_dir(hs_dir: &str, uid: u32, gid: u32, log: &mut Vec<String>) -> R<()> {
    match lstat(hs_dir) {
        Ok(st) if !is_type(&st, libc::S_IFDIR) => {
            let kind = if is_type(&st, libc::S_IFLNK) {
                "a symlink"
            } else {
                "not a directory"
            };
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

pub fn write_all(fd: &Fd, data: &[u8]) -> R<()> {
    write_all_via(data, |chunk| {
        // SAFETY: writing from a live slice to an open descriptor.
        let n = unsafe { libc::write(fd.0, chunk.as_ptr().cast(), chunk.len()) };
        usize::try_from(n).map_err(|_| py::last_errno())
    })
}

/// The write(2) loop: retries EINTR, and treats a write of 0 bytes as an I/O error
/// rather than looping for ever on it.
fn write_all_via(data: &[u8], mut write: impl FnMut(&[u8]) -> Result<usize, i32>) -> R<()> {
    let mut off = 0;
    while off < data.len() {
        match write(&data[off..]) {
            Ok(0) => return Err(PyErr::os(libc::EIO)),
            Ok(n) => off += n,
            Err(libc::EINTR) => {}
            Err(e) => return Err(PyErr::os(e)),
        }
    }
    Ok(())
}

/// Write a file through O_NOFOLLOW|O_TRUNC, then fchmod/fchown that descriptor.
pub fn write_nofollow(path: &str, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> R<()> {
    let fd = open(
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
        mode,
    )?;
    write_all(&fd, data)?;
    fchmod(&fd, mode)?;
    if let Some((u, g)) = owner {
        fchown(&fd, u, g)?;
    }
    Ok(())
}

/// _write_dropped_mappings.
pub fn write_dropped_mappings(
    path: &str,
    reasons: &[String],
    uid: u32,
    gid: u32,
    log: &mut Vec<String>,
) {
    if reasons.is_empty() {
        let c = cpath(path);
        // SAFETY: valid C string.
        if unsafe { libc::unlink(c.as_ptr()) } != 0 {
            let e = py::last_errno();
            if e != libc::ENOENT {
                log.push(format!(
                    "Warning: could not remove {path}: {}",
                    py::oserror_path(e, path)
                ));
            }
        }
        return;
    }
    let body = reasons.join("\n") + "\n";
    match write_nofollow(path, body.as_bytes(), 0o600, Some((uid, gid))) {
        Ok(()) => log.push(format!(
            "Recorded {} dropped mapping(s) in {path}",
            reasons.len()
        )),
        Err(e) => log.push(format!("Warning: could not write {path}: {e}")),
    }
}

pub const ADDRESS_FILE_MAX: usize = 256;

/// _read_small_regular_file: no-follow, non-blocking, regular files only, capped.
pub fn read_small_regular_file(path: &str, max_bytes: usize) -> R<Vec<u8>> {
    let fd = open(
        path,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )?;
    read_capped(&fd, path, max_bytes)
}

/// The read half of _read_small_regular_file on an open descriptor: refuse
/// anything but a regular file, then one read of at most `max_bytes + 1`, so a
/// longer file is noticed without reading it all. `shown` names it in errors.
fn read_capped(fd: &Fd, shown: &str, max_bytes: usize) -> R<Vec<u8>> {
    if !is_type(&fstat(fd)?, libc::S_IFREG) {
        return Err(PyErr {
            errno: Some(libc::EINVAL),
            msg: format!("[Errno 22] {shown} is not a regular file"),
        });
    }
    let mut buf = vec![0u8; max_bytes + 1];
    // os.read() returns after ONE read; a regular file returns all it has.
    let n = loop {
        // SAFETY: reading into a live buffer.
        let n = unsafe { libc::read(fd.0, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            break n as usize;
        }
        let e = py::last_errno();
        if e != libc::EINTR {
            return Err(PyErr::os(e));
        }
    };
    buf.truncate(n);
    if buf.len() > max_bytes {
        return Err(PyErr {
            errno: Some(libc::EFBIG),
            msg: format!("[Errno 27] {shown} is larger than {max_bytes} bytes"),
        });
    }
    Ok(buf)
}

pub fn is_onion(s: &str) -> bool {
    s.len() == 62
        && s.ends_with(".onion")
        && s[..56]
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
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
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        return fallback_hex8(t, std::process::id());
    }
    hex8(b)
}

fn hex8(b: [u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fallback_hex8(nanos: u128, pid: u32) -> String {
    format!("{:016x}", (nanos as u64) ^ u64::from(pid))
}

fn openat(dirfd: &Fd, name: &str, flags: i32, mode: u32, shown: &str) -> R<Fd> {
    let c = cpath(name);
    // SAFETY: dirfd is an open directory; name is a single component.
    let fd = unsafe {
        libc::openat(
            dirfd.0,
            c.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        Err(PyErr::os_path(py::last_errno(), shown))
    } else {
        Ok(Fd(fd))
    }
}

/// read_small_regular_file relative to a held directory descriptor.
fn read_small_at(dirfd: &Fd, name: &str, shown: &str, max_bytes: usize) -> R<Vec<u8>> {
    let fd = openat(
        dirfd,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
        shown,
    )?;
    read_capped(&fd, shown, max_bytes)
}

/// Remembers which publication failures were already reported.
#[derive(Default)]
pub struct PublishState {
    warned: Vec<(String, String, i32)>,
}

impl PublishState {
    fn warn_once(&mut self, name: &str, action: &str, e: &PyErr, log: &mut Vec<String>) {
        let errno = e.errno.unwrap_or(0);
        if errno == libc::ENOENT {
            return;
        }
        let key = (
            name.to_string(),
            action.split(' ').next().unwrap_or("").to_string(),
            errno,
        );
        if self.warned.contains(&key) {
            return;
        }
        self.warned.push(key);
        log.push(format!(
            "Warning: cannot publish the .onion address for {name}: {action} failed: {}. The service itself is \
             unaffected -- read the address with 'hiddenforge show --name {name}' in the container instead. (Reported \
             once; further identical failures are not repeated.)",
            py::strerror(errno)
        ));
    }
}

/// _publish_addresses: copy each valid hostname to <keys_root>/<name>.onion, atomically,
/// once the gate says the service is reachable.
///
/// `read_as_owner` reads a hostname file the supervisor itself may not open:
/// under rootless Podman root holds no DAC_OVERRIDE and the service directory
/// is the tor user's 0700, so 2.x never published the address there at all.
/// The file read is the same no-follow, regular-file, size-capped read, done
/// by a process running as the directory's owner; only the public address
/// comes back, and it is validated here exactly as a direct read is.
/// Create a file that must not exist yet, in a held directory: never reuses or
/// follows anything already at that name (a planted file or link is an error).
fn create_new_at(dir: &Fd, name: &str, shown: &str) -> R<Fd> {
    openat(
        dir,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o644,
        shown,
    )
}

pub fn publish_addresses(
    hs_dirs: &[String],
    keys_root: &str,
    keys_fd: &Fd,
    gate: &mut dyn FnMut() -> bool,
    read_as_owner: &dyn Fn(&str) -> Option<Vec<u8>>,
    state: &mut PublishState,
    log: &mut Vec<String>,
) {
    let mut pending = Vec::new();
    for hs_dir in hs_dirs {
        let name = hs_dir.rsplit('/').next().unwrap_or(hs_dir).to_string();
        let path = format!("{hs_dir}/hostname");
        let raw = match read_small_regular_file(&path, ADDRESS_FILE_MAX) {
            Ok(r) => r,
            Err(e) if e.is_permission() => match read_as_owner(&path) {
                Some(r) => r,
                None => {
                    state.warn_once(&name, "read hostname", &e, log);
                    continue;
                }
            },
            Err(e) => {
                state.warn_once(&name, "read hostname", &e, log);
                continue;
            }
        };
        let Some(onion) = ascii_strip(&raw) else {
            continue;
        };
        if !is_onion(&onion) {
            continue;
        }
        let target = format!("{keys_root}/{name}.onion");
        if let Ok(cur) = read_small_at(keys_fd, &format!("{name}.onion"), &target, ADDRESS_FILE_MAX)
        {
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
        // Every operation is relative to `keys_fd`, opened once at startup: under
        // rootless Podman root cannot traverse the tor-owned DataDirectory that
        // holds the key volume, so a path would fail where the descriptor works,
        // and a descriptor cannot be redirected by a planted link either.
        let tmp_name = format!(".{name}.onion.{}.tmp", random_hex8());
        let tmp = format!("{keys_root}/{tmp_name}");
        let target_name = format!("{name}.onion");
        let mut created = false;
        let r = (|| -> R<()> {
            let fd = create_new_at(keys_fd, &tmp_name, &tmp)?;
            created = true;
            write_all(&fd, format!("{onion}\n").as_bytes())?;
            fchmod(&fd, 0o644)?;
            drop(fd);
            let (a, b) = (cpath(&tmp_name), cpath(&target_name));
            // SAFETY: both names are single components relative to the same open directory.
            if unsafe { libc::renameat(keys_fd.0, a.as_ptr(), keys_fd.0, b.as_ptr()) } != 0 {
                let e = py::last_errno();
                return Err(PyErr {
                    errno: Some(e),
                    msg: format!(
                        "[Errno {e}] {}: {} -> {}",
                        py::strerror(e),
                        py::py_repr(&tmp),
                        py::py_repr(&target)
                    ),
                });
            }
            Ok(())
        })();
        if let Err(e) = r {
            if created {
                let c = cpath(&tmp_name);
                // SAFETY: relative to the held directory; failure is ignored as in 2.x.
                unsafe { libc::unlinkat(keys_fd.0, c.as_ptr(), 0) };
            }
            state.warn_once(&name, &format!("write {target}"), &e, log);
            continue;
        }
        log.push(format!("Published address for {name}: {onion}"));
    }
}

/// uid/gid of a user from /etc/passwd (pwd.getpwnam without NSS).
pub fn getpwnam(name: &str) -> Option<(u32, u32, String)> {
    parse_passwd(&std::fs::read_to_string("/etc/passwd").ok()?, name)
}

/// (uid, gid, home) of `name` in passwd-format `text`: the first line whose
/// first field is `name`, with the seven fields a passwd line has.
fn parse_passwd(text: &str, name: &str) -> Option<(u32, u32, String)> {
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 7 && f[0] == name)
            .then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?, f[5].to_string())))?
    })
}

/// A scratch directory for tests that is removed when dropped, also when the
/// test panics. Directories a test made unreadable are opened up first.
#[cfg(test)]
pub(crate) mod testtmp {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    pub struct Tmp(String);

    impl Tmp {
        pub fn new(tag: &str) -> Tmp {
            let d = std::env::temp_dir().join(format!("hf-{tag}-{}", super::random_hex8()));
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d.to_string_lossy().into_owned())
        }
    }

    impl std::ops::Deref for Tmp {
        type Target = str;
        fn deref(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Display for Tmp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    fn unlock(p: &Path) {
        if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    unlock(&e.path());
                }
            }
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            unlock(Path::new(&self.0));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn write_all_via_retries_eintr_finishes_short_writes_and_refuses_zero() {
        let mut got = Vec::new();
        let mut calls = 0;
        write_all_via(b"abcdef", |c| {
            calls += 1;
            match calls {
                1 => Err(libc::EINTR),
                2 => {
                    got.extend_from_slice(&c[..2]);
                    Ok(2)
                }
                _ => {
                    got.extend_from_slice(c);
                    Ok(c.len())
                }
            }
        })
        .unwrap();
        assert_eq!((got.as_slice(), calls), (&b"abcdef"[..], 3));
        let mut zero_calls = 0;
        let e = write_all_via(b"x", |_| {
            zero_calls += 1;
            assert!(zero_calls < 3, "looped on a zero-byte write");
            Ok(0)
        })
        .unwrap_err();
        assert_eq!(e.msg, "[Errno 5] Input/output error");
        let e = write_all_via(b"x", |_| Err(libc::ENOSPC)).unwrap_err();
        assert_eq!(e.msg, "[Errno 28] No space left on device");
        write_all_via(b"", |_| panic!("no write for empty data")).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn create_new_at_refuses_an_existing_file_or_link_and_writes_nothing_through_it() {
        let d = tmpdir("cna");
        let kfd = open_dir_nofollow(&d).unwrap();
        let victim = format!("{d}/victim");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, format!("{d}/link")).unwrap();
        std::fs::write(format!("{d}/file"), b"keep").unwrap();
        for name in ["link", "file"] {
            let Err(e) = create_new_at(&kfd, name, name) else {
                panic!("{name}: opened an existing entry");
            };
            assert_eq!(e.errno, Some(libc::EEXIST), "{name}: {}", e.msg);
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(std::fs::read(format!("{d}/file")).unwrap(), b"keep");
        let Ok(fd) = create_new_at(&kfd, "new", "new") else {
            panic!("could not create a new file");
        };
        write_all(&fd, b"x").unwrap();
        assert_eq!(std::fs::read(format!("{d}/new")).unwrap(), b"x");
    }

    #[test]
    fn mkdir_p_steps_keep_relative_paths_relative() {
        assert_eq!(mkdir_p_steps("/a//b/"), ["/a", "/a/b"]);
        assert_eq!(mkdir_p_steps("a/b"), ["a", "a/b"]);
        assert_eq!(mkdir_p_steps("/"), Vec::<String>::new());
    }

    use super::testtmp::Tmp;

    fn tmpdir(tag: &str) -> Tmp {
        Tmp::new(tag)
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
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn service_dir_becomes_0700() {
        let d = tmpdir("mode");
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        std::fs::set_permissions(&svc, std::fs::Permissions::from_mode(0o775)).unwrap();
        // SAFETY: getuid/getgid have no preconditions.
        let (u, g) = unsafe { (libc::getuid(), libc::getgid()) };
        prepare_hs_dir(&svc, u, g, &mut vec![]).unwrap();
        assert_eq!(
            std::fs::metadata(&svc).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn hardlink_is_not_chowned_and_is_named() {
        let d = tmpdir("hl");
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        std::fs::write(format!("{d}/outside"), b"x").unwrap();
        std::fs::hard_link(
            format!("{d}/outside"),
            format!("{svc}/hs_ed25519_secret_key"),
        )
        .unwrap();
        let mut log = vec![];
        // SAFETY: as above.
        let (u, g) = unsafe { (libc::getuid(), libc::getgid()) };
        chown_r(&svc, u, g, &mut log).unwrap();
        assert!(log.iter().any(|l| l.contains("2 hard links")));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn fifo_hostname_does_not_block_and_publish_is_atomic() {
        let d = tmpdir("pub");
        let svc = format!("{d}/a");
        std::fs::create_dir(&svc).unwrap();
        let c = cpath(&format!("{svc}/hostname"));
        // SAFETY: valid C string.
        unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        let mut st = PublishState::default();
        let mut log = vec![];
        let kfd = open_dir_nofollow(&d).unwrap();
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut || true,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert!(log.iter().any(|l| l.contains("read hostname failed")));
        std::fs::remove_file(format!("{svc}/hostname")).unwrap();
        let onion = format!("{}.onion", "a".repeat(56));
        std::fs::write(format!("{svc}/hostname"), format!("{onion}\n")).unwrap();
        let mut log = vec![];
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut || false,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert!(
            std::fs::metadata(format!("{d}/a.onion")).is_err(),
            "gate said no"
        );
        publish_addresses(&[svc], &d, &kfd, &mut || true, &|_| None, &mut st, &mut log);
        assert_eq!(
            std::fs::read_to_string(format!("{d}/a.onion")).unwrap(),
            format!("{onion}\n")
        );
        assert_eq!(
            std::fs::metadata(format!("{d}/a.onion"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    fn me() -> (u32, u32) {
        // SAFETY: getuid/getgid have no preconditions.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn mode_of(p: &str) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(p: &str, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mkfifo(p: &str) {
        let c = cpath(p);
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    fn not_root() -> bool {
        !crate::privs::is_root()
    }

    /// Run `f` on its own thread and fail (instead of hanging the run) if it blocks.
    fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the call blocked")
    }

    fn cloexec(fd: &Fd) -> bool {
        // SAFETY: fcntl on an open descriptor.
        unsafe { libc::fcntl(fd.0, libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
    }

    // ---- G3: opens and I/O -------------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn open_and_openat_report_python_style_errors_and_set_cloexec() {
        let d = tmpdir("open");
        std::fs::write(format!("{d}/f"), b"x").unwrap();
        let p = format!("{d}/nope");
        let Err(e) = open(&p, libc::O_RDONLY, 0) else {
            panic!("opened a missing file")
        };
        assert_eq!(e.errno, Some(libc::ENOENT));
        assert_eq!(e.msg, format!("[Errno 2] No such file or directory: '{p}'"));
        let fd = open(&format!("{d}/f"), libc::O_RDONLY, 0).unwrap();
        assert!(cloexec(&fd));
        // O_CREAT takes the mode argument
        let created = open(
            &format!("{d}/made"),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .unwrap();
        assert_eq!(mode_of(&format!("{d}/made")), 0o600);
        drop(created);

        let dirfd = open_dir_nofollow(&d).unwrap();
        let Err(e) = openat(&dirfd, "missing", libc::O_RDONLY, 0, "shown/path") else {
            panic!("opened a missing file")
        };
        assert_eq!(
            e.msg, "[Errno 2] No such file or directory: 'shown/path'",
            "the error names the shown path, not the relative name"
        );
        let fd = openat(&dirfd, "f", libc::O_RDONLY, 0, "f").unwrap();
        assert!(cloexec(&fd));
        let made = openat(
            &dirfd,
            "made2",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o640,
            "made2",
        )
        .unwrap();
        drop(made);
        assert_eq!(mode_of(&format!("{d}/made2")), 0o640);
    }

    #[test]
    fn fd_closes_its_descriptor_on_drop() {
        let mut p = [0i32; 2];
        // SAFETY: pipe2 fills two descriptors.
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_NONBLOCK) }, 0);
        let (r, w) = (Fd(p[0]), Fd(p[1]));
        let mut b = [0u8; 1];
        // SAFETY: reading one byte into a live buffer.
        let n = unsafe { libc::read(r.0, b.as_mut_ptr().cast(), 1) };
        assert_eq!(
            (n, py::last_errno()),
            (-1, libc::EAGAIN),
            "a writer is open"
        );
        drop(w);
        // SAFETY: as above.
        let n = unsafe { libc::read(r.0, b.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 0, "closing the last writer gives EOF");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn open_dir_nofollow_refuses_files_and_links() {
        let d = tmpdir("odn");
        std::fs::create_dir(format!("{d}/real")).unwrap();
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        symlink(format!("{d}/real"), format!("{d}/link")).unwrap();
        let fd = open_dir_nofollow(&format!("{d}/real")).unwrap();
        assert!(is_type(&fstat(&fd).unwrap(), libc::S_IFDIR));
        assert!(cloexec(&fd));
        for name in ["file", "link"] {
            let p = format!("{d}/{name}");
            let Err(e) = open_dir_nofollow(&p) else {
                panic!("{name}: opened as a directory")
            };
            assert_eq!(
                (e.errno, e.msg),
                (
                    Some(libc::ENOTDIR),
                    format!("[Errno 20] Not a directory: '{p}'")
                )
            );
        }
        // a missing directory is its own error
        let Err(e) = open_dir_nofollow(&format!("{d}/none")) else {
            panic!()
        };
        assert_eq!(e.errno, Some(libc::ENOENT));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn lstat_fstat_and_imode_report_what_the_inode_says() {
        let d = tmpdir("stat");
        let f = format!("{d}/f");
        std::fs::write(&f, b"abc").unwrap();
        chmod(&f, 0o4755);
        symlink(&f, format!("{d}/l")).unwrap();
        let st = lstat(&f).unwrap();
        assert!(is_type(&st, libc::S_IFREG) && !is_type(&st, libc::S_IFDIR));
        assert_eq!((imode(&st), st.st_size), (0o4755, 3));
        // lstat does not follow; fstat of an opened file agrees with lstat of it
        assert!(is_type(&lstat(&format!("{d}/l")).unwrap(), libc::S_IFLNK));
        let fd = open(&f, libc::O_RDONLY, 0).unwrap();
        assert_eq!(imode(&fstat(&fd).unwrap()), 0o4755);
        let Err(e) = lstat(&format!("{d}/none")) else {
            panic!()
        };
        assert_eq!(
            e.msg,
            format!("[Errno 2] No such file or directory: '{d}/none'")
        );
        // imode keeps setuid/setgid/sticky and drops the file type
        let mut fake: libc::stat = unsafe { std::mem::zeroed() };
        fake.st_mode = libc::S_IFDIR | 0o3777;
        assert_eq!(imode(&fake), 0o3777);
        fake.st_mode = libc::S_IFREG | 0o600;
        assert_eq!(imode(&fake), 0o600);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_small_regular_file_enforces_the_cap_exactly() {
        let d = tmpdir("cap");
        let p = format!("{d}/f");
        std::fs::write(&p, vec![b'a'; 256]).unwrap();
        assert_eq!(read_small_regular_file(&p, 256).unwrap(), vec![b'a'; 256]);
        std::fs::write(&p, vec![b'a'; 257]).unwrap();
        let e = read_small_regular_file(&p, 256).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EFBIG),
                format!("[Errno 27] {p} is larger than 256 bytes")
            )
        );
        std::fs::write(&p, b"").unwrap();
        assert_eq!(read_small_regular_file(&p, 256).unwrap(), b"");
        assert_eq!(read_small_regular_file(&p, 0).unwrap(), b"");
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(
            read_small_regular_file(&p, 0).unwrap_err().errno,
            Some(libc::EFBIG)
        );
        assert_eq!(read_small_regular_file(&p, 1).unwrap(), b"x");
        assert_eq!(ADDRESS_FILE_MAX, 256);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_small_regular_file_refuses_links_fifos_and_directories() {
        let d = tmpdir("kinds");
        std::fs::write(format!("{d}/real"), b"secret").unwrap();
        symlink(format!("{d}/real"), format!("{d}/link")).unwrap();
        let link = format!("{d}/link");
        let e = read_small_regular_file(&link, 64).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::ELOOP),
                format!("[Errno 40] Too many levels of symbolic links: '{link}'")
            )
        );
        let fifo = format!("{d}/fifo");
        mkfifo(&fifo);
        let f2 = fifo.clone();
        let e = within(move || read_small_regular_file(&f2, 64)).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EINVAL),
                format!("[Errno 22] {fifo} is not a regular file")
            )
        );
        let e = read_small_regular_file(&d, 64).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EINVAL),
                format!("[Errno 22] {d} is not a regular file")
            )
        );
        let e = read_small_regular_file(&format!("{d}/none"), 64).unwrap_err();
        assert_eq!(e.errno, Some(libc::ENOENT));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_small_at_matches_the_path_reader_and_names_the_shown_path() {
        let d = tmpdir("at");
        let dirfd = open_dir_nofollow(&d).unwrap();
        std::fs::write(format!("{d}/f"), vec![b'z'; 10]).unwrap();
        assert_eq!(
            read_small_at(&dirfd, "f", "S/f", 10).unwrap(),
            vec![b'z'; 10]
        );
        let e = read_small_at(&dirfd, "f", "S/f", 9).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EFBIG),
                "[Errno 27] S/f is larger than 9 bytes".to_string()
            )
        );
        std::fs::write(format!("{d}/e"), b"").unwrap();
        assert_eq!(read_small_at(&dirfd, "e", "S/e", 9).unwrap(), b"");
        symlink(format!("{d}/f"), format!("{d}/l")).unwrap();
        let e = read_small_at(&dirfd, "l", "S/l", 99).unwrap_err();
        assert_eq!(e.errno, Some(libc::ELOOP));
        assert!(e.msg.ends_with(": 'S/l'"), "{}", e.msg);
        std::fs::create_dir(format!("{d}/sub")).unwrap();
        let e = read_small_at(&dirfd, "sub", "S/sub", 99).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EINVAL),
                "[Errno 22] S/sub is not a regular file".to_string()
            )
        );
        mkfifo(&format!("{d}/fifo"));
        let e = within(move || read_small_at(&dirfd, "fifo", "S/fifo", 99)).unwrap_err();
        assert_eq!(e.errno, Some(libc::EINVAL));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn write_nofollow_sets_the_mode_despite_umask_truncates_and_refuses_links() {
        let d = tmpdir("wnf");
        let (u, g) = me();
        // new file: the requested mode, even one the default umask would trim
        let p = format!("{d}/new");
        write_nofollow(&p, b"hello", 0o666, None).unwrap();
        assert_eq!(
            (std::fs::read(&p).unwrap(), mode_of(&p)),
            (b"hello".to_vec(), 0o666)
        );
        // existing file: truncated, not appended to, and its old mode replaced
        let q = format!("{d}/old");
        std::fs::write(&q, b"a much longer old content").unwrap();
        chmod(&q, 0o644);
        write_nofollow(&q, b"short", 0o640, Some((u, g))).unwrap();
        assert_eq!(
            (std::fs::read(&q).unwrap(), mode_of(&q)),
            (b"short".to_vec(), 0o640)
        );
        write_nofollow(&q, b"", 0o600, None).unwrap();
        assert_eq!(
            (std::fs::read(&q).unwrap(), mode_of(&q)),
            (Vec::new(), 0o600)
        );
        // a symlink is refused and its target left alone
        let target = format!("{d}/target");
        std::fs::write(&target, b"keep").unwrap();
        let l = format!("{d}/lnk");
        symlink(&target, &l).unwrap();
        let e = write_nofollow(&l, b"overwritten", 0o600, None).unwrap_err();
        assert_eq!(e.errno, Some(libc::ELOOP));
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        // a directory cannot be written
        assert_eq!(
            write_nofollow(&d, b"x", 0o600, None).unwrap_err().errno,
            Some(libc::EISDIR)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn fchown_and_chown_errors_are_python_style() {
        if !not_root() {
            return;
        }
        let d = tmpdir("fchown");
        let (u, g) = me();
        let p = format!("{d}/f");
        let e = write_nofollow(&p, b"x", 0o600, Some((u.wrapping_add(1), g))).unwrap_err();
        assert_eq!(
            (e.errno, e.msg.as_str()),
            (Some(libc::EPERM), "[Errno 1] Operation not permitted")
        );
        let fd = open(&p, libc::O_RDONLY, 0).unwrap();
        fchown(&fd, u, g).unwrap();
        assert_eq!(
            fchown(&fd, u.wrapping_add(1), g).unwrap_err().errno,
            Some(1)
        );
        // chown to the owner we already are is accepted through a path too
        lchown(&p, u, g).unwrap();
        let e = lchown(&p, u.wrapping_add(1), g).unwrap_err();
        assert_eq!(e.msg, format!("[Errno 1] Operation not permitted: '{p}'"));
        fchmod(&fd, 0o640).unwrap();
        assert_eq!(mode_of(&p), 0o640);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn pyerr_is_permission_is_exactly_eacces_and_eperm() {
        for (errno, want) in [
            (libc::EACCES, true),
            (libc::EPERM, true),
            (libc::ENOENT, false),
            (libc::EEXIST, false),
            (libc::EINVAL, false),
            (libc::EROFS, false),
        ] {
            assert_eq!(PyErr::os(errno).is_permission(), want, "errno {errno}");
        }
        assert!(!PyErr::runtime("x".into()).is_permission());
        assert_eq!(PyErr::runtime("boom".into()).to_string(), "boom");
    }

    // ---- G4: directories and metadata --------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn mkdir_p_creates_every_level_and_accepts_existing_directories() {
        let d = tmpdir("mkp");
        let deep = format!("{d}/a/b/c");
        mkdir_p(&deep).unwrap();
        assert!(is_type(&lstat(&deep).unwrap(), libc::S_IFDIR));
        mkdir_p(&deep).unwrap();
        // a symlink to a directory counts as an existing directory (pathlib exist_ok)
        symlink(format!("{d}/a"), format!("{d}/via")).unwrap();
        mkdir_p(&format!("{d}/via/b")).unwrap();
        // a regular file in the way is FileExistsError, naming the file
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        let e = mkdir_p(&format!("{d}/file")).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EEXIST),
                format!("[Errno 17] File exists: '{d}/file'")
            )
        );
        // ...and so is a dangling symlink, whose target does not exist
        symlink(format!("{d}/gone"), format!("{d}/dangling")).unwrap();
        assert_eq!(
            mkdir_p(&format!("{d}/dangling")).unwrap_err().errno,
            Some(libc::EEXIST)
        );
        // anything below a file fails at the file, not further down
        let e = mkdir_p(&format!("{d}/file/sub")).unwrap_err();
        assert_eq!(e.msg, format!("[Errno 17] File exists: '{d}/file'"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn mkdir_p_reports_other_errors_at_the_failing_level() {
        if !not_root() {
            return;
        }
        let d = tmpdir("mkpro");
        let ro = format!("{d}/ro");
        std::fs::create_dir(&ro).unwrap();
        chmod(&ro, 0o500);
        let e = mkdir_p(&format!("{ro}/x/y")).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EACCES),
                format!("[Errno 13] Permission denied: '{ro}/x'")
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn mkdir_owned_creates_0700_and_fixes_an_existing_mode() {
        let d = tmpdir("mko");
        let (u, g) = me();
        let p = format!("{d}/new");
        mkdir_owned(&p, u, g).unwrap();
        assert_eq!(mode_of(&p), 0o700);
        let q = format!("{d}/old");
        std::fs::create_dir(&q).unwrap();
        chmod(&q, 0o775);
        mkdir_owned(&q, u, g).unwrap();
        assert_eq!(mode_of(&q), 0o700);
        // idempotent
        mkdir_owned(&q, u, g).unwrap();
        assert_eq!(mode_of(&q), 0o700);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn mkdir_owned_refuses_anything_that_is_not_a_real_directory() {
        let d = tmpdir("mkor");
        let (u, g) = me();
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        std::fs::create_dir(format!("{d}/real")).unwrap();
        symlink(format!("{d}/real"), format!("{d}/link")).unwrap();
        for name in ["file", "link"] {
            let p = format!("{d}/{name}");
            let e = mkdir_owned(&p, u, g).unwrap_err();
            assert_eq!(
                (e.errno, e.msg),
                (None, format!("{p} is not a directory; refusing to use it")),
                "{name}"
            );
        }
        // the link's target was not touched
        assert_eq!(mode_of(&format!("{d}/real")) & 0o700, 0o700);
        // a missing parent: mkdir fails and says where
        let p = format!("{d}/no/such/dir");
        let e = mkdir_owned(&p, u, g).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::ENOENT),
                format!("[Errno 2] No such file or directory: '{p}'")
            )
        );
        // lstat failing for another reason is returned as it is
        let p = format!("{d}/file/below");
        assert_eq!(
            mkdir_owned(&p, u, g).unwrap_err().errno,
            Some(libc::ENOTDIR)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn prepare_hs_dir_creates_missing_directories_and_secures_them() {
        let d = tmpdir("phd");
        let (u, g) = me();
        let svc = format!("{d}/x/svc");
        let mut log = vec![];
        prepare_hs_dir(&svc, u, g, &mut log).unwrap();
        assert_eq!(mode_of(&svc), 0o700);
        assert!(log.is_empty(), "{log:?}");
        prepare_hs_dir(&svc, u, g, &mut log).unwrap();
        assert!(log.is_empty(), "{log:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn prepare_hs_dir_refuses_links_and_non_directories_with_the_exact_text() {
        let d = tmpdir("phdr");
        let (u, g) = me();
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        std::fs::create_dir(format!("{d}/real")).unwrap();
        symlink(format!("{d}/real"), format!("{d}/link")).unwrap();
        for (name, kind) in [("file", "not a directory"), ("link", "a symlink")] {
            let p = format!("{d}/{name}");
            let e = prepare_hs_dir(&p, u, g, &mut vec![]).unwrap_err();
            assert_eq!(
                e.msg,
                format!("{p} in the key volume is {kind}; refusing to use it as a service directory. Replace it with the real directory (restore it from a backup).")
            );
        }
        // an lstat error that is not "missing" is returned, not repaired
        let p = format!("{d}/file/below");
        let e = prepare_hs_dir(&p, u, g, &mut vec![]).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::ENOTDIR),
                format!("[Errno 20] Not a directory: '{p}'")
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn prepare_hs_dir_accepts_a_directory_the_tor_user_already_owns() {
        if !not_root() {
            return;
        }
        // Mode 0 is the stand-in for "the tor user's 0700 directory the supervisor
        // can no longer open": opening it fails with EACCES, then the already-prepared
        // check must pass on owner and mode.
        let d = tmpdir("phdo");
        let (u, g) = me();
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        chmod(&svc, 0o000);
        let mut log = vec![];
        prepare_hs_dir(&svc, u, g, &mut log).unwrap();
        assert_eq!(
            log,
            [format!(
                "{svc} is already the tor user's (prepared by a previous start); nothing to change."
            )]
        );
        assert_eq!(mode_of(&svc), 0, "nothing was changed");
        // the same directory for a different expected owner: the error stands
        let e = prepare_hs_dir(&svc, u.wrapping_add(1), g, &mut vec![]).unwrap_err();
        assert_eq!(
            (e.errno, e.msg),
            (
                Some(libc::EACCES),
                format!("[Errno 13] Permission denied: '{svc}'")
            )
        );
        // group or other access means it is not the locked-down directory
        for mode in [0o070, 0o007, 0o077, 0o040, 0o004] {
            chmod(&svc, mode); // owner bits clear, so it still cannot be opened
            let mut log = vec![];
            let r = prepare_hs_dir(&svc, u, g, &mut log);
            assert_eq!(
                r.unwrap_err().errno,
                Some(libc::EACCES),
                "mode {mode:o} must not count as prepared"
            );
            assert!(log.is_empty(), "{log:?}");
        }
        chmod(&svc, 0o700);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn secure_service_dir_makes_0700_and_explains_what_it_cannot_do() {
        let d = tmpdir("ssd");
        let svc = format!("{d}/svc");
        std::fs::create_dir(&svc).unwrap();
        chmod(&svc, 0o700);
        secure_service_dir(&svc).unwrap();
        for mode in [0o775, 0o755, 0o500, 0o1700, 0o2700] {
            chmod(&svc, mode);
            secure_service_dir(&svc).unwrap();
            assert_eq!(mode_of(&svc), 0o700, "from {mode:o}");
        }
        std::fs::write(format!("{d}/file"), b"x").unwrap();
        assert_eq!(
            secure_service_dir(&format!("{d}/file")).unwrap_err().errno,
            Some(libc::ENOTDIR)
        );
        symlink(&svc, format!("{d}/link")).unwrap();
        assert_eq!(
            secure_service_dir(&format!("{d}/link")).unwrap_err().errno,
            Some(libc::ENOTDIR)
        );
        if not_root() {
            // "/" belongs to root and is not 0700: the error says how to fix it
            let st = lstat("/").unwrap();
            let e = secure_service_dir("/").unwrap_err();
            assert_eq!(e.errno, Some(libc::EPERM));
            assert_eq!(
                e.msg,
                format!(
                    "[Errno 1] / is mode 0o{:o}, which Tor refuses, and it cannot be set to 0700 here (it belongs to uid {} and the runtime grants no FOWNER). Run `chmod 700` on it on the host.",
                    imode(&st),
                    st.st_uid
                )
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn chmod_dir_nofollow_honours_only_if_root_owned() {
        let d = tmpdir("cdn");
        let p = format!("{d}/dir");
        std::fs::create_dir(&p).unwrap();
        chmod(&p, 0o755);
        if not_root() {
            // we own it, root does not: with the filter it is left alone
            assert!(!chmod_dir_nofollow(&p, 0o711, true).unwrap());
            assert_eq!(mode_of(&p), 0o755);
        }
        assert!(chmod_dir_nofollow(&p, 0o711, false).unwrap());
        assert_eq!(mode_of(&p), 0o711);
        // a link is refused, whatever the flag
        symlink(&p, format!("{d}/lnk")).unwrap();
        let l = format!("{d}/lnk");
        assert_eq!(
            chmod_dir_nofollow(&l, 0o700, false).unwrap_err().errno,
            Some(libc::ENOTDIR)
        );
        assert_eq!(
            chmod_dir_nofollow(&l, 0o700, true).unwrap_err().errno,
            Some(libc::ENOTDIR)
        );
        assert_eq!(mode_of(&p), 0o711);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn chown_one_chowns_files_dirs_and_links_without_noise() {
        let d = tmpdir("co");
        let (u, g) = me();
        let f = format!("{d}/f");
        std::fs::write(&f, b"x").unwrap();
        std::fs::create_dir(format!("{d}/sub")).unwrap();
        std::fs::create_dir(format!("{d}/sub/inner")).unwrap(); // sub now has 3 links
        symlink("/nonexistent-target", format!("{d}/dangling")).unwrap();
        let mut log = vec![];
        chown_one(&f, u, g, &mut log).unwrap();
        chown_one(&format!("{d}/sub"), u, g, &mut log).unwrap();
        // a link is chowned itself, so even a dangling one works
        chown_one(&format!("{d}/dangling"), u, g, &mut log).unwrap();
        assert!(log.is_empty(), "{log:?}");
        let e = chown_one(&format!("{d}/none"), u, g, &mut log).unwrap_err();
        assert_eq!(e.errno, Some(libc::ENOENT));
        if not_root() {
            let e = chown_one(&f, u.wrapping_add(1), g, &mut log).unwrap_err();
            assert_eq!(
                e.msg, "[Errno 1] Operation not permitted",
                "fchown through the descriptor, so no path in the text"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn chown_one_names_hard_links_devices_and_sockets_and_does_not_touch_them() {
        let d = tmpdir("cow");
        let (u, g) = me();
        std::fs::write(format!("{d}/a"), b"x").unwrap();
        std::fs::hard_link(format!("{d}/a"), format!("{d}/b")).unwrap();
        let mut log = vec![];
        chown_one(&format!("{d}/b"), u, g, &mut log).unwrap();
        assert_eq!(
            log,
            [format!(
                "Warning: not taking ownership of {d}/b: it has 2 hard links, so it is also a file outside this directory. Tor never hard-links its key files; remove the extra links."
            )]
        );
        // even a chown that would be refused is skipped, proving no fchown ran
        if not_root() {
            let mut log = vec![];
            chown_one(&format!("{d}/a"), u.wrapping_add(1), g, &mut log).unwrap();
            assert_eq!(log.len(), 1);
        }
        // a character device (never opened) and a socket
        let want = |p: &str| {
            format!("Warning: not taking ownership of {p} in the key volume: it is a device node or socket, which does not belong there.")
        };
        let mut log = vec![];
        chown_one("/dev/null", u.wrapping_add(1), g, &mut log).unwrap();
        assert_eq!(log, [want("/dev/null")]);
        let sock = format!("{d}/sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let mut log = vec![];
        chown_one(&sock, u.wrapping_add(1), g, &mut log).unwrap();
        assert_eq!(log, [want(&sock)]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn chown_one_does_not_block_on_a_fifo() {
        let d = tmpdir("cof");
        let (u, g) = me();
        let fifo = format!("{d}/fifo");
        mkfifo(&fifo);
        let log = within(move || {
            let mut log = vec![];
            chown_one(&fifo, u, g, &mut log).unwrap();
            log
        });
        assert!(log.is_empty());
    }

    #[test]
    fn is_label_and_is_onion_check_length_alphabet_and_suffix() {
        let lab = "a".repeat(56);
        assert!(is_label(&lab));
        assert!(!is_label(&"a".repeat(55)));
        assert!(!is_label(&"a".repeat(57)));
        assert!(!is_label(""));
        assert!(is_label(&"az27".repeat(14)));
        for bad in [
            'A', '0', '1', '8', '9', '{', '`', '-', '.', '/', ':', '\u{e9}',
        ] {
            let s = format!("{}{bad}", "a".repeat(55));
            if bad.len_utf8() == 1 {
                assert!(!is_label(&s), "{bad:?} accepted");
            }
            let s = format!("{bad}{}", "a".repeat(55));
            assert!(!is_label(&s), "{bad:?} accepted first");
        }
        let on = format!("{lab}.onion");
        assert!(is_onion(&on));
        assert!(!is_onion(&format!("{}.onion", "a".repeat(55))));
        assert!(!is_onion(&format!("{}.onion", "a".repeat(57))));
        assert!(!is_onion(&format!("{lab}.onioN")));
        assert!(!is_onion(&format!("{lab}.onyon")));
        assert!(!is_onion(&format!("{lab}xonion")));
        assert!(!is_onion(&lab));
        assert!(!is_onion(&format!("{lab}.onion\n")));
        assert!(!is_onion(&format!("{}1.onion", "a".repeat(55))));
        assert!(!is_onion(&format!("{}A.onion", "a".repeat(55))));
        assert!(!is_onion(&format!("{}8.onion", "a".repeat(55))));
        assert!(is_onion(&format!("{}7.onion", "a".repeat(55))));
        assert!(is_onion(&format!("{}2.onion", "z".repeat(55))));
        assert!(is_onion(&format!("2{}.onion", "7".repeat(55))));
        assert!(!is_onion(&format!("{}\u{e9}.onion", "a".repeat(54))));
    }

    // ---- G5: dropped mappings, publish, passwd, names -----------------------

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn write_dropped_mappings_writes_one_reason_per_line_with_mode_0600() {
        let d = tmpdir("wdm");
        let (u, g) = me();
        let p = format!("{d}/dropped");
        let mut log = vec![];
        write_dropped_mappings(&p, &["first".into(), "second".into()], u, g, &mut log);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "first\nsecond\n");
        assert_eq!(mode_of(&p), 0o600);
        assert_eq!(log, [format!("Recorded 2 dropped mapping(s) in {p}")]);
        // rewritten, not appended, when the set changes
        let mut log = vec![];
        write_dropped_mappings(&p, &["only".into()], u, g, &mut log);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "only\n");
        assert_eq!(log, [format!("Recorded 1 dropped mapping(s) in {p}")]);
        // an empty set removes the file, silently, and silently again when it is gone
        let mut log = vec![];
        write_dropped_mappings(&p, &[], u, g, &mut log);
        write_dropped_mappings(&p, &[], u, g, &mut log);
        assert!(!std::path::Path::new(&p).exists());
        assert!(log.is_empty(), "{log:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn write_dropped_mappings_reports_failures_in_the_log() {
        let d = tmpdir("wdmf");
        let (u, g) = me();
        let mut log = vec![];
        let p = format!("{d}/no/such/dropped");
        write_dropped_mappings(&p, &["r".into()], u, g, &mut log);
        assert_eq!(
            log,
            [format!(
                "Warning: could not write {p}: [Errno 2] No such file or directory: '{p}'"
            )]
        );
        // removal that fails for a reason other than "absent" is reported
        let dir = format!("{d}/isdir");
        std::fs::create_dir(&dir).unwrap();
        let mut log = vec![];
        write_dropped_mappings(&dir, &[], u, g, &mut log);
        assert_eq!(
            log,
            [format!(
                "Warning: could not remove {dir}: [Errno 21] Is a directory: '{dir}'"
            )]
        );
        // a link at the path is not followed when writing
        std::fs::write(format!("{d}/t"), b"keep").unwrap();
        symlink(format!("{d}/t"), format!("{d}/l")).unwrap();
        let mut log = vec![];
        write_dropped_mappings(&format!("{d}/l"), &["r".into()], u, g, &mut log);
        assert_eq!(std::fs::read(format!("{d}/t")).unwrap(), b"keep");
        assert!(log[0].starts_with("Warning: could not write "), "{log:?}");
    }

    fn onion_of(c: char) -> String {
        format!("{}.onion", c.to_string().repeat(56))
    }

    fn pub_setup(tag: &str) -> (Tmp, Fd) {
        let d = tmpdir(tag);
        let fd = open_dir_nofollow(&d).unwrap();
        (d, fd)
    }

    fn mk_service(d: &str, name: &str, hostname: Option<&[u8]>) -> String {
        let svc = format!("{d}/{name}");
        std::fs::create_dir(&svc).unwrap();
        if let Some(h) = hostname {
            std::fs::write(format!("{svc}/hostname"), h).unwrap();
        }
        svc
    }

    fn leftovers(d: &str) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with('.') || n.ends_with(".tmp"))
            .collect();
        v.sort();
        v
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_writes_0644_logs_and_leaves_no_temp_file() {
        let (d, kfd) = pub_setup("pub1");
        let on = onion_of('a');
        let svc = mk_service(&d, "a", Some(format!("{on}\n").as_bytes()));
        let (mut st, mut log) = (PublishState::default(), vec![]);
        publish_addresses(&[svc], &d, &kfd, &mut || true, &|_| None, &mut st, &mut log);
        let target = format!("{d}/a.onion");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), format!("{on}\n"));
        assert_eq!(mode_of(&target), 0o644);
        assert_eq!(log, [format!("Published address for a: {on}")]);
        assert_eq!(leftovers(&d), Vec::<String>::new());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_is_idempotent_and_replaces_a_stale_copy() {
        let (d, kfd) = pub_setup("pub2");
        let (on1, on2) = (onion_of('a'), onion_of('b'));
        let svc = mk_service(&d, "a", Some(format!("{on1}\n").as_bytes()));
        let target = format!("{d}/a.onion");
        let (mut st, mut log) = (PublishState::default(), vec![]);
        let gate_calls = std::cell::Cell::new(0);
        let mut gate = || {
            gate_calls.set(gate_calls.get() + 1);
            true
        };
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut gate,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert_eq!((gate_calls.get(), log.len()), (1, 1));
        // nothing new: no gate call, no write, no log
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut gate,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert_eq!((gate_calls.get(), log.len()), (1, 1));
        // an equal copy with different whitespace is still the same address
        std::fs::write(&target, format!("  {on1}\r\n")).unwrap();
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut gate,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert_eq!((gate_calls.get(), log.len()), (1, 1));
        // the service's address changed: the stale copy is replaced
        std::fs::write(format!("{svc}/hostname"), format!("{on2}\n")).unwrap();
        publish_addresses(
            std::slice::from_ref(&svc),
            &d,
            &kfd,
            &mut gate,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            format!("{on2}\n")
        );
        assert_eq!(
            log.last().unwrap(),
            &format!("Published address for a: {on2}")
        );
        assert_eq!(gate_calls.get(), 2);
        // a damaged published copy (not an address, not ASCII) is rewritten too
        for junk in [&b"garbage"[..], &b"\xff\xfe\n"[..], &vec![b'a'; 300][..]] {
            std::fs::write(&target, junk).unwrap();
            publish_addresses(
                std::slice::from_ref(&svc),
                &d,
                &kfd,
                &mut gate,
                &|_| None,
                &mut st,
                &mut log,
            );
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                format!("{on2}\n")
            );
        }
        assert_eq!(leftovers(&d), Vec::<String>::new());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_replaces_a_planted_link_instead_of_following_it() {
        let (d, kfd) = pub_setup("pub3");
        let svc = mk_service(&d, "a", Some(format!("{}\n", onion_of('a')).as_bytes()));
        std::fs::write(format!("{d}/victim"), b"keep").unwrap();
        symlink(format!("{d}/victim"), format!("{d}/a.onion")).unwrap();
        let (mut st, mut log) = (PublishState::default(), vec![]);
        publish_addresses(&[svc], &d, &kfd, &mut || true, &|_| None, &mut st, &mut log);
        assert_eq!(std::fs::read(format!("{d}/victim")).unwrap(), b"keep");
        assert_eq!(
            std::fs::read_to_string(format!("{d}/a.onion")).unwrap(),
            format!("{}\n", onion_of('a'))
        );
        assert!(!is_type(
            &lstat(&format!("{d}/a.onion")).unwrap(),
            libc::S_IFLNK
        ));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_skips_invalid_hostnames_without_a_word() {
        let (d, kfd) = pub_setup("pub4");
        let mut services = vec![];
        let bad: [(&str, Vec<u8>); 5] = [
            (
                "nonascii",
                format!("{}\u{e9}\n", onion_of('a')).into_bytes(),
            ),
            ("short", b"abc.onion\n".to_vec()),
            ("upper", format!("{}\n", onion_of('A')).into_bytes()),
            ("empty", Vec::new()),
            (
                "twolines",
                format!("{}\n{}\n", onion_of('a'), onion_of('a')).into_bytes(),
            ),
        ];
        for (name, content) in &bad {
            services.push(mk_service(&d, name, Some(content)));
        }
        let (mut st, mut log) = (PublishState::default(), vec![]);
        let gate_calls = std::cell::Cell::new(0);
        publish_addresses(
            &services,
            &d,
            &kfd,
            &mut || {
                gate_calls.set(1);
                true
            },
            &|_| None,
            &mut st,
            &mut log,
        );
        assert!(log.is_empty(), "{log:?}");
        assert_eq!(gate_calls.get(), 0, "nothing to publish, so no gate call");
        for (name, _) in &bad {
            assert!(!std::path::Path::new(&format!("{d}/{name}.onion")).exists());
        }
        // a gate that says no keeps everything pending and writes nothing
        let good = mk_service(&d, "good", Some(format!("{}\n", onion_of('c')).as_bytes()));
        publish_addresses(
            std::slice::from_ref(&good),
            &d,
            &kfd,
            &mut || false,
            &|_| None,
            &mut st,
            &mut log,
        );
        assert!(log.is_empty());
        assert!(!std::path::Path::new(&format!("{d}/good.onion")).exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_asks_the_owner_only_after_a_permission_error() {
        if !not_root() {
            return;
        }
        let (d, kfd) = pub_setup("pub5");
        let on = onion_of('d');
        // unreadable by us: the owner-side reader is asked, with this exact path
        let svc = mk_service(&d, "locked", Some(format!("{on}\n").as_bytes()));
        chmod(&format!("{svc}/hostname"), 0o000);
        // missing hostname and a FIFO are not permission errors: the owner is not asked
        let missing = mk_service(&d, "missing", None);
        let fifo = mk_service(&d, "fifo", None);
        mkfifo(&format!("{fifo}/hostname"));
        let asked = std::cell::RefCell::new(Vec::new());
        let reader = |p: &str| {
            asked.borrow_mut().push(p.to_string());
            Some(format!("{on}\n").into_bytes())
        };
        let (mut st, mut log) = (PublishState::default(), vec![]);
        let services = [missing, fifo.clone(), svc.clone()];
        publish_addresses(
            &services,
            &d,
            &kfd,
            &mut || true,
            &reader,
            &mut st,
            &mut log,
        );
        assert_eq!(*asked.borrow(), [format!("{svc}/hostname")]);
        assert_eq!(
            std::fs::read_to_string(format!("{d}/locked.onion")).unwrap(),
            format!("{on}\n")
        );
        // the FIFO warns (EINVAL) once; the missing file is silent; the locked one published
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(
            log[0].contains("for fifo: read hostname failed: Invalid argument."),
            "{log:?}"
        );
        assert_eq!(log[1], format!("Published address for locked: {on}"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_warns_once_when_even_the_owner_cannot_read() {
        if !not_root() {
            return;
        }
        let (d, kfd) = pub_setup("pub6");
        let svc = mk_service(
            &d,
            "locked",
            Some(format!("{}\n", onion_of('d')).as_bytes()),
        );
        chmod(&format!("{svc}/hostname"), 0o000);
        let (mut st, mut log) = (PublishState::default(), vec![]);
        for _ in 0..3 {
            publish_addresses(
                std::slice::from_ref(&svc),
                &d,
                &kfd,
                &mut || true,
                &|_| None,
                &mut st,
                &mut log,
            );
        }
        assert_eq!(
            log,
            ["Warning: cannot publish the .onion address for locked: read hostname failed: Permission denied. The service itself is unaffected -- read the address with 'hiddenforge show --name locked' in the container instead. (Reported once; further identical failures are not repeated.)".to_string()]
        );
        assert!(!std::path::Path::new(&format!("{d}/locked.onion")).exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn publish_addresses_cleans_up_and_warns_once_when_the_rename_fails() {
        let (d, kfd) = pub_setup("pub7");
        let svc = mk_service(&d, "a", Some(format!("{}\n", onion_of('a')).as_bytes()));
        // a directory where the address file belongs: rename cannot replace it
        std::fs::create_dir(format!("{d}/a.onion")).unwrap();
        let (mut st, mut log) = (PublishState::default(), vec![]);
        for _ in 0..2 {
            publish_addresses(
                std::slice::from_ref(&svc),
                &d,
                &kfd,
                &mut || true,
                &|_| None,
                &mut st,
                &mut log,
            );
        }
        assert_eq!(
            log,
            [format!(
                "Warning: cannot publish the .onion address for a: write {d}/a.onion failed: Is a directory. The service itself is unaffected -- read the address with 'hiddenforge show --name a' in the container instead. (Reported once; further identical failures are not repeated.)"
            )]
        );
        assert_eq!(
            leftovers(&d),
            Vec::<String>::new(),
            "the temp file is removed"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn warn_once_is_per_service_action_and_errno_and_ignores_enoent() {
        let mut st = PublishState::default();
        let mut log = vec![];
        st.warn_once("a", "read hostname", &PyErr::os(libc::ENOENT), &mut log);
        assert!(log.is_empty());
        st.warn_once("a", "read hostname", &PyErr::os(libc::EACCES), &mut log);
        st.warn_once("a", "read hostname", &PyErr::os(libc::EACCES), &mut log);
        assert_eq!(log.len(), 1);
        // another service, another action word, another errno: each reported once; the
        // path after the action word does not count (Python keys on action.split()[0])
        st.warn_once("b", "read hostname", &PyErr::os(libc::EACCES), &mut log);
        st.warn_once("a", "write /k/a.onion", &PyErr::os(libc::EACCES), &mut log);
        st.warn_once("a", "write /k/other", &PyErr::os(libc::EACCES), &mut log);
        st.warn_once("a", "read hostname", &PyErr::os(libc::EIO), &mut log);
        assert_eq!(log.len(), 4, "{log:?}");
        // an error without an errno counts as errno 0, and is reported
        st.warn_once("c", "read hostname", &PyErr::runtime("x".into()), &mut log);
        assert_eq!(log.len(), 5);
        assert!(log[4].contains("failed: Success."), "{}", log[4]);
    }

    #[test]
    fn parse_passwd_picks_the_first_matching_user_and_its_fields() {
        let text = "root:x:0:0:root:/root:/bin/sh\n\
                    tor:x:100:101:Tor:/var/lib/tor:/sbin/nologin\n\
                    tor:x:200:201:Tor again:/elsewhere:/bin/sh\n";
        assert_eq!(
            parse_passwd(text, "tor"),
            Some((100, 101, "/var/lib/tor".to_string()))
        );
        assert_eq!(
            parse_passwd(text, "root"),
            Some((0, 0, "/root".to_string()))
        );
        assert_eq!(parse_passwd(text, "to"), None);
        assert_eq!(parse_passwd(text, "tor2"), None);
        assert_eq!(parse_passwd(text, ""), None);
        assert_eq!(parse_passwd("", "tor"), None);
        // exactly seven fields is a full line; six is not
        assert_eq!(
            parse_passwd("tor:x:1:2:c:/h:/s", "tor"),
            Some((1, 2, "/h".to_string()))
        );
        assert_eq!(parse_passwd("tor:x:1:2:c:/h", "tor"), None);
        // the name must be the first field, not any field
        assert_eq!(parse_passwd("x:tor:1:2:c:/h:/s", "tor"), None);
        // a field-count above seven (extra colons in the shell) still parses
        assert_eq!(
            parse_passwd("tor:x:1:2:c:/h:/s:extra", "tor"),
            Some((1, 2, "/h".to_string()))
        );
        // a non-numeric id is not a user
        assert_eq!(parse_passwd("tor:x:abc:2:c:/h:/s", "tor"), None);
        assert_eq!(parse_passwd("tor:x:1:abc:c:/h:/s", "tor"), None);
        assert_eq!(getpwnam("root").map(|(u, g, _)| (u, g)), Some((0, 0)));
        assert_eq!(getpwnam("no-such-user-hf-test"), None);
    }

    #[test]
    fn hex_names_are_sixteen_zero_padded_lowercase_digits() {
        assert_eq!(
            hex8([0x00, 0x01, 0xab, 0xff, 0x10, 0x7f, 0x80, 0xfe]),
            "0001abff107f80fe"
        );
        assert_eq!(hex8([0; 8]), "0000000000000000");
        // the fallback XORs the low 64 bits of the clock with the pid
        assert_eq!(fallback_hex8(0b0110, 0b0011), "0000000000000005");
        assert_eq!(fallback_hex8((1u128 << 64) | 0x10, 3), "0000000000000013");
        assert_eq!(fallback_hex8(0, 0), "0000000000000000");
        assert_eq!(fallback_hex8(u128::MAX, 0), "ffffffffffffffff");
        // the live generator draws all 64 bits: a clock-based name starts with 0 or 1
        let names: Vec<String> = (0..64).map(|_| random_hex8()).collect();
        for n in &names {
            assert!(
                n.len() == 16
                    && n.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "{n}"
            );
        }
        assert!(names.iter().any(|n| n.as_bytes()[0] > b'1'), "{names:?}");
        let mut uniq = names.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), names.len());
    }

    #[test]
    fn onion_regex() {
        assert!(is_onion(&format!("{}.onion", "a2".repeat(28))));
        assert!(!is_onion(&format!("{}.onion", "a1".repeat(28))));
    }
}
