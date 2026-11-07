//! Client authorization (opt-in): Tor v3 "restricted discovery".
//!
//! With at least one `<HiddenServiceDir>/authorized_clients/<client>.auth` file,
//! Tor encrypts the service descriptor to the listed clients' x25519 keys, so
//! anyone without a matching private key cannot even learn the service's
//! introduction points, let alone connect. The address alone stops being enough.
//!
//! This module makes and removes those files. The keypair is generated with
//! OpenSSL (the image's libcrypto, as everywhere else). The service keeps only
//! the public half; the private half is printed once, for the operator to hand
//! to the client, and is never written to the service's volume.
//!
//! File formats are Tor's (tor manual, CLIENT AUTHORIZATION):
//!   service: `descriptor:x25519:<base32 public key>`
//!   client:  `<56-char onion>:descriptor:x25519:<base32 private key>`

use crate::fsops;
use crate::keycrypt::Secret;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

#[link(name = "crypto")]
extern "C" {
    fn EVP_PKEY_Q_keygen(
        libctx: *mut c_void,
        propq: *const c_char,
        typ: *const c_char,
        ...
    ) -> *mut c_void;
    fn EVP_PKEY_get_raw_public_key(pkey: *const c_void, out: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_get_raw_private_key(pkey: *const c_void, out: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_free(pkey: *mut c_void);
}

struct Pkey(*mut c_void);
impl Drop for Pkey {
    fn drop(&mut self) {
        // SAFETY: freeing the key we generated (EVP_PKEY_free wipes it).
        unsafe { EVP_PKEY_free(self.0) };
    }
}

/// A fresh x25519 keypair: (public, private), 32 bytes each.
pub fn x25519_keypair() -> Result<([u8; 32], Secret), String> {
    // SAFETY: OpenSSL keygen with static NUL-terminated strings; the result is
    // checked for NULL and freed by Pkey.
    let key = Pkey(unsafe {
        EVP_PKEY_Q_keygen(std::ptr::null_mut(), std::ptr::null(), c"X25519".as_ptr())
    });
    if key.0.is_null() {
        return Err("x25519 key generation failed".into());
    }
    let mut public = [0u8; 32];
    let mut private = Secret(vec![0u8; 32]);
    let (mut lp, mut ls) = (32usize, 32usize);
    // SAFETY: both buffers are 32 bytes and the lengths say so.
    let ok = unsafe {
        EVP_PKEY_get_raw_public_key(key.0, public.as_mut_ptr(), &mut lp) == 1
            && EVP_PKEY_get_raw_private_key(key.0, private.0.as_mut_ptr(), &mut ls) == 1
    };
    if !ok || lp != 32 || ls != 32 {
        return Err("cannot read the x25519 key".into());
    }
    Ok((public, private))
}

/// RFC 4648 base32, upper case, no padding (Tor's encoding for these keys).
pub fn base32_upper(data: &[u8]) -> String {
    crate::sha3::base32_lower(data).to_ascii_uppercase()
}

pub fn client_name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !n.starts_with('-')
}

pub fn auth_dir(keys: &str, service: &str) -> String {
    format!("{keys}/{service}/authorized_clients")
}

/// Add a client: write its .auth (public key only), return the line the
/// client must put in its ClientOnionAuthDir as `<anything>.auth_private`.
pub fn add(keys: &str, service: &str, client: &str, onion: &str) -> Result<String, String> {
    let dir = auth_dir(keys, service);
    let path = format!("{dir}/{client}.auth");
    if fsops::lstat(&path).is_ok() {
        return Err(format!(
            "client {client} already exists for {service}; remove it first to issue a new key"
        ));
    }
    match fsops::lstat(&dir) {
        Ok(st) if fsops::is_type(&st, libc::S_IFDIR) => {}
        Ok(_) => return Err(format!("{dir} is not a directory; refusing to write there")),
        Err(_) => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("cannot create {dir}: {e}"))?;
        }
    }
    let (public, private) = x25519_keypair()?;
    let line = format!("descriptor:x25519:{}\n", base32_upper(&public));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // create_new: never overwrite an existing client's key.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("cannot create {path}: {e}"))?;
        f.write_all(line.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("cannot write {path}: {e}"))?;
    }
    let host = onion.trim().trim_end_matches(".onion");
    Ok(format!(
        "{host}:descriptor:x25519:{}",
        base32_upper(&private.0)
    ))
}

/// Remove a client: its .auth file goes, and with it its access (after a restart).
pub fn remove(keys: &str, service: &str, client: &str) -> Result<bool, String> {
    let path = format!("{}/{client}.auth", auth_dir(keys, service));
    match fsops::lstat(&path) {
        Ok(st) if fsops::is_type(&st, libc::S_IFREG) => std::fs::remove_file(&path)
            .map(|()| true)
            .map_err(|e| format!("cannot remove {path}: {e}")),
        Ok(_) => Err(format!(
            "{path} is not a regular file; refusing to touch it"
        )),
        Err(_) => Ok(false),
    }
}

/// The clients a service authorizes, sorted.
pub fn list(keys: &str, service: &str) -> Result<Vec<String>, String> {
    let dir = auth_dir(keys, service);
    let rd = match std::fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(format!("cannot read {dir}: {e}")),
    };
    let mut out: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".auth"))
                .map(String::from)
        })
        .filter(|n| client_name_ok(n))
        .collect();
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_is_fresh_and_encodes_like_tor() {
        let (p1, s1) = x25519_keypair().unwrap();
        let (p2, _) = x25519_keypair().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(s1.0, vec![0u8; 32]);
        let b = base32_upper(&p1);
        assert_eq!(b.len(), 52); // 32 bytes -> 52 base32 chars, no padding
        assert!(b
            .bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)));
    }

    #[test]
    fn rfc4648_vector() {
        assert_eq!(base32_upper(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn names() {
        assert!(client_name_ok("alice"));
        assert!(client_name_ok("desk_2"));
        assert!(!client_name_ok("../x"));
        assert!(!client_name_ok("-x"));
        assert!(!client_name_ok("A"));
        assert!(!client_name_ok(""));
    }

    #[test]
    fn add_list_remove() {
        let d = std::env::temp_dir().join(format!("hf-ca-{}", std::process::id()));
        std::fs::create_dir_all(d.join("svc")).unwrap();
        let keys = d.to_string_lossy().into_owned();
        let onion = "a".repeat(56) + ".onion";
        let line = add(&keys, "svc", "alice", &onion).unwrap();
        assert!(line.starts_with(&format!("{}:descriptor:x25519:", "a".repeat(56))));
        assert!(
            add(&keys, "svc", "alice", &onion).is_err(),
            "a second key for the same name"
        );
        let auth = std::fs::read_to_string(d.join("svc/authorized_clients/alice.auth")).unwrap();
        assert!(auth.starts_with("descriptor:x25519:") && auth.ends_with('\n'));
        assert!(
            !auth.contains(line.rsplit(':').next().unwrap()),
            "private key on the service side"
        );
        assert_eq!(list(&keys, "svc").unwrap(), vec!["alice".to_string()]);
        assert!(remove(&keys, "svc", "alice").unwrap());
        assert!(!remove(&keys, "svc", "alice").unwrap());
        assert!(list(&keys, "svc").unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
