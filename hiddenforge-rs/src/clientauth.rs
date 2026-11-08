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
    use crate::fsops::testtmp::Tmp;
    use std::os::unix::fs::{symlink, PermissionsExt};

    extern "C" {
        fn EVP_PKEY_new_raw_private_key(
            typ: c_int,
            e: *mut c_void,
            key: *const u8,
            keylen: usize,
        ) -> *mut c_void;
    }

    /// The x25519 public key of a private key, by OpenSSL, independent of how
    /// x25519_keypair produced the pair.
    fn public_of(private: &[u8]) -> [u8; 32] {
        const NID_X25519: c_int = 1034;
        // SAFETY: a 32-byte key buffer; the key object is freed by Pkey.
        let k = Pkey(unsafe {
            EVP_PKEY_new_raw_private_key(NID_X25519, std::ptr::null_mut(), private.as_ptr(), 32)
        });
        assert!(!k.0.is_null());
        let mut out = [0u8; 32];
        let mut len = 32usize;
        // SAFETY: 32-byte buffer, length says so.
        assert_eq!(
            unsafe { EVP_PKEY_get_raw_public_key(k.0, out.as_mut_ptr(), &mut len) },
            1
        );
        assert_eq!(len, 32);
        out
    }

    fn b32_decode(s: &str) -> Vec<u8> {
        let (mut bits, mut acc, mut out) = (0u32, 0u32, Vec::new());
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'2'..=b'7' => c - b'2' + 26,
                _ => panic!("not base32: {c}"),
            };
            acc = (acc << 5) | u32::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        out
    }

    fn mode_of(p: &str) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn onion() -> String {
        "a".repeat(56) + ".onion"
    }

    #[test]
    fn keypair_is_fresh_and_consistent() {
        let (p1, s1) = x25519_keypair().unwrap();
        let (p2, s2) = x25519_keypair().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(s1.0, s2.0);
        assert_eq!(s1.0.len(), 32);
        assert_ne!(s1.0, vec![0u8; 32]);
        assert_ne!(p1, [0u8; 32]);
        // the public half really belongs to the private half
        assert_eq!(public_of(&s1.0), p1);
        assert_eq!(public_of(&s2.0), p2);
        assert_ne!(public_of(&s1.0), p2);
        let b = base32_upper(&p1);
        assert_eq!(b.len(), 52); // 32 bytes -> 52 base32 chars, no padding
        assert!(b
            .bytes()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(&c)));
    }

    #[test]
    fn base32_matches_rfc_4648_without_padding() {
        // RFC 4648 section 10 test vectors, '=' padding removed
        for (plain, want) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_upper(plain.as_bytes()), want, "{plain:?}");
        }
        assert_eq!(b32_decode("MZXW6YTBOI"), b"foobar");
    }

    #[test]
    fn names() {
        for ok in [
            "alice",
            "desk_2",
            "a",
            "0",
            "_x",
            "x-",
            "a-b",
            &"a".repeat(63),
        ] {
            assert!(client_name_ok(ok), "{ok:?}");
        }
        for bad in [
            "",
            "../x",
            "-x",
            "-",
            "A",
            "alIce",
            "a b",
            "a.b",
            "a/b",
            "a\n",
            "é",
            "x\0y",
            &"a".repeat(64),
        ] {
            assert!(!client_name_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn auth_dir_is_below_the_service_directory() {
        assert_eq!(auth_dir("/k", "svc"), "/k/svc/authorized_clients");
    }

    #[test]
    fn add_writes_the_public_key_only_and_returns_the_client_line() {
        let d = Tmp::new("caadd");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        let line = add(&d, "svc", "alice", &onion()).unwrap();
        let (head, private_b32) = line.rsplit_once(':').unwrap();
        assert_eq!(head, format!("{}:descriptor:x25519", "a".repeat(56)));
        assert_eq!(private_b32.len(), 52);
        let file = format!("{d}/svc/authorized_clients/alice.auth");
        let auth = std::fs::read_to_string(&file).unwrap();
        assert!(
            auth.starts_with("descriptor:x25519:") && auth.ends_with('\n'),
            "{auth:?}"
        );
        assert_eq!(auth.matches('\n').count(), 1);
        // the file holds the public half of the key the client was given
        let private = b32_decode(private_b32);
        assert_eq!(private.len(), 32);
        assert_eq!(
            auth,
            format!("descriptor:x25519:{}\n", base32_upper(&public_of(&private)))
        );
        assert!(
            !auth.contains(private_b32),
            "private key on the service side"
        );
        // modes: private directory, private file
        assert_eq!(mode_of(&format!("{d}/svc/authorized_clients")), 0o700);
        assert_eq!(mode_of(&file), 0o600);
    }

    #[test]
    fn add_a_second_client_gets_its_own_key_and_keeps_the_first() {
        let d = Tmp::new("caadd2");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        let a = add(&d, "svc", "alice", &onion()).unwrap();
        let first = std::fs::read(format!("{d}/svc/authorized_clients/alice.auth")).unwrap();
        let b = add(&d, "svc", "bob", &onion()).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            std::fs::read(format!("{d}/svc/authorized_clients/alice.auth")).unwrap(),
            first
        );
        assert_eq!(list(&d, "svc").unwrap(), ["alice", "bob"]);
    }

    #[test]
    fn add_refuses_an_existing_client_a_dangling_link_and_a_bad_directory() {
        let d = Tmp::new("caaddref");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        add(&d, "svc", "alice", &onion()).unwrap();
        let before = std::fs::read(format!("{d}/svc/authorized_clients/alice.auth")).unwrap();
        assert_eq!(
            add(&d, "svc", "alice", &onion()),
            Err("client alice already exists for svc; remove it first to issue a new key".into())
        );
        assert_eq!(
            std::fs::read(format!("{d}/svc/authorized_clients/alice.auth")).unwrap(),
            before
        );
        // a link at the client's file name, even a dangling one, is "already exists"
        symlink(
            "/nonexistent",
            format!("{d}/svc/authorized_clients/eve.auth"),
        )
        .unwrap();
        assert!(add(&d, "svc", "eve", &onion())
            .unwrap_err()
            .starts_with("client eve already exists"));
        // the authorized_clients entry is a file or a link, not a directory
        std::fs::create_dir(format!("{d}/f")).unwrap();
        std::fs::write(format!("{d}/f/authorized_clients"), b"x").unwrap();
        let dir = format!("{d}/f/authorized_clients");
        assert_eq!(
            add(&d, "f", "c", &onion()),
            Err(format!("{dir} is not a directory; refusing to write there"))
        );
        std::fs::create_dir_all(format!("{d}/l/real")).unwrap();
        symlink(format!("{d}/l/real"), format!("{d}/l/authorized_clients")).unwrap();
        let dir = format!("{d}/l/authorized_clients");
        assert_eq!(
            add(&d, "l", "c", &onion()),
            Err(format!("{dir} is not a directory; refusing to write there"))
        );
        assert_eq!(std::fs::read_dir(format!("{d}/l/real")).unwrap().count(), 0);
        // a missing service directory cannot get its client directory
        let dir = format!("{d}/nosvc/authorized_clients");
        assert_eq!(
            add(&d, "nosvc", "c", &onion()),
            Err(format!(
                "cannot create {dir}: No such file or directory (os error 2)"
            ))
        );
    }

    #[test]
    fn add_returns_the_onion_label_without_whitespace_or_suffix() {
        let d = Tmp::new("caonion");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        let label = "b".repeat(56);
        for (i, given) in [
            format!("{label}.onion"),
            format!("  {label}.onion\n"),
            label.clone(),
        ]
        .iter()
        .enumerate()
        {
            let line = add(&d, "svc", &format!("c{i}"), given).unwrap();
            assert!(
                line.starts_with(&format!("{label}:descriptor:x25519:")),
                "{given:?}: {line}"
            );
            assert!(!line.contains(".onion"));
        }
    }

    #[test]
    fn list_is_sorted_and_only_shows_valid_auth_files() {
        let d = Tmp::new("calist");
        assert_eq!(
            list(&d, "svc").unwrap(),
            Vec::<String>::new(),
            "no directory"
        );
        std::fs::create_dir_all(format!("{d}/svc/authorized_clients")).unwrap();
        assert_eq!(
            list(&d, "svc").unwrap(),
            Vec::<String>::new(),
            "empty directory"
        );
        let dir = format!("{d}/svc/authorized_clients");
        for f in [
            "zed.auth",
            "alice.auth",
            "bob_2.auth",
            "notes.txt",
            "Carol.auth",
            "-dash.auth",
            ".auth",
            "alice.auth.bak",
            "nosuffix",
        ] {
            std::fs::write(format!("{dir}/{f}"), b"x").unwrap();
        }
        assert_eq!(list(&d, "svc").unwrap(), ["alice", "bob_2", "zed"]);
    }

    #[test]
    fn list_reports_an_unreadable_directory() {
        let d = Tmp::new("calisterr");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        std::fs::write(format!("{d}/svc/authorized_clients"), b"x").unwrap();
        let dir = format!("{d}/svc/authorized_clients");
        assert_eq!(
            list(&d, "svc"),
            Err(format!("cannot read {dir}: Not a directory (os error 20)"))
        );
        // a missing service is just empty, not an error
        assert_eq!(list(&d, "nope"), Ok(vec![]));
    }

    #[test]
    fn remove_deletes_regular_files_and_refuses_anything_else() {
        let d = Tmp::new("caremove");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        add(&d, "svc", "alice", &onion()).unwrap();
        assert_eq!(remove(&d, "svc", "alice"), Ok(true));
        assert_eq!(remove(&d, "svc", "alice"), Ok(false));
        assert_eq!(remove(&d, "nosvc", "alice"), Ok(false));
        assert_eq!(list(&d, "svc").unwrap(), Vec::<String>::new());
        let dir = format!("{d}/svc/authorized_clients");
        // a symlink (even to a regular file) and a directory are left alone
        std::fs::write(format!("{d}/victim"), b"keep").unwrap();
        symlink(format!("{d}/victim"), format!("{dir}/ln.auth")).unwrap();
        std::fs::create_dir(format!("{dir}/dr.auth")).unwrap();
        for n in ["ln", "dr"] {
            let p = format!("{dir}/{n}.auth");
            assert_eq!(
                remove(&d, "svc", n),
                Err(format!("{p} is not a regular file; refusing to touch it"))
            );
            assert!(std::fs::symlink_metadata(&p).is_ok());
        }
        assert_eq!(std::fs::read(format!("{d}/victim")).unwrap(), b"keep");
    }

    #[test]
    fn remove_reports_a_file_it_cannot_delete() {
        if crate::privs::is_root() {
            return;
        }
        let d = Tmp::new("caremoveerr");
        std::fs::create_dir(format!("{d}/svc")).unwrap();
        add(&d, "svc", "alice", &onion()).unwrap();
        let dir = format!("{d}/svc/authorized_clients");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(
            remove(&d, "svc", "alice"),
            Err(format!(
                "cannot remove {dir}/alice.auth: Permission denied (os error 13)"
            ))
        );
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(list(&d, "svc").unwrap(), ["alice"]);
    }
}
