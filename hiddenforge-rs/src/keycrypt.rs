//! Key encryption at rest (opt-in): the onion secret key is kept on the volume
//! only as an authenticated envelope, and decrypted at every start into the
//! tmpfs DataDirectory, where Tor uses it. The plaintext key never touches the
//! volume again.
//!
//! Envelope ("HFKEY1"), the i2pforge keycrypt layout with AES-256-GCM:
//!   magic(6) | aead id(1)=0x02 AES-256-GCM | kdf id(1)=0x01 scrypt |
//!   log2N(u32 BE) | r(u32 BE) | p(u32 BE) | salt_len(1)=16 | salt(16) |
//!   nonce(12) | ciphertext | tag(16)
//! The whole 49-byte header is the GCM additional data, so no parameter can be
//! changed without failing authentication.
//!
//! Cryptography is OpenSSL's (the libcrypto Tor already links), never hand
//! written: EVP_PBE_scrypt and EVP_aes_256_gcm. Key material is wiped with
//! OPENSSL_cleanse as soon as it is no longer needed.

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

pub const MAGIC: &[u8; 6] = b"HFKEY1";
const AEAD_AES256GCM: u8 = 0x02;
const KDF_SCRYPT: u8 = 0x01;
pub const LOG2_N: u32 = 17; // N = 131072, ~128 MiB working set
pub const R: u32 = 8;
pub const P: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 49;
const MAXMEM: u64 = 256 * 1024 * 1024;
pub const MIN_PASSPHRASE_CHARS: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 4096;
const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

#[link(name = "crypto")]
extern "C" {
    fn EVP_PBE_scrypt(
        pass: *const c_char,
        passlen: usize,
        salt: *const u8,
        saltlen: usize,
        n: u64,
        r: u64,
        p: u64,
        maxmem: u64,
        key: *mut u8,
        keylen: usize,
    ) -> c_int;
    fn EVP_CIPHER_CTX_new() -> *mut c_void;
    fn EVP_CIPHER_CTX_free(ctx: *mut c_void);
    fn EVP_aes_256_gcm() -> *const c_void;
    fn EVP_EncryptInit_ex(
        ctx: *mut c_void,
        cipher: *const c_void,
        engine: *mut c_void,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_EncryptUpdate(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut c_int,
        inp: *const u8,
        inl: c_int,
    ) -> c_int;
    fn EVP_EncryptFinal_ex(ctx: *mut c_void, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_DecryptInit_ex(
        ctx: *mut c_void,
        cipher: *const c_void,
        engine: *mut c_void,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    fn EVP_DecryptUpdate(
        ctx: *mut c_void,
        out: *mut u8,
        outl: *mut c_int,
        inp: *const u8,
        inl: c_int,
    ) -> c_int;
    fn EVP_DecryptFinal_ex(ctx: *mut c_void, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_CIPHER_CTX_ctrl(ctx: *mut c_void, typ: c_int, arg: c_int, ptr: *mut c_void) -> c_int;
    fn RAND_bytes(buf: *mut u8, num: c_int) -> c_int;
    fn OPENSSL_cleanse(ptr: *mut c_void, len: usize);
}

/// Bytes that are wiped when dropped.
pub struct Secret(pub Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: wiping our own buffer.
        unsafe { OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    // SAFETY: filling our own buffer.
    if unsafe { RAND_bytes(b.as_mut_ptr(), n as c_int) } != 1 {
        return Err("RAND_bytes failed".into());
    }
    Ok(b)
}

/// The scrypt parameters this code is willing to run: RFC 7914 requires
/// N < 2^(128*r/8), i.e. log2(N) < 16*r, and the working set OpenSSL needs,
/// 128*r*(N+p+2) bytes, must fit in MAXMEM.
fn check_scrypt_params(log2n: u32, r: u32, p: u32) -> Result<(), String> {
    if log2n >= 16 * r {
        return Err(format!("refusing scrypt log2(N)={log2n} with r={r}"));
    }
    let need = 128u64 * u64::from(r) * ((1u64 << log2n) + u64::from(p) + 2);
    if need > MAXMEM {
        return Err(format!(
            "refusing scrypt parameters needing {} MiB",
            need / (1024 * 1024)
        ));
    }
    Ok(())
}

fn derive(pass: &[u8], salt: &[u8], log2n: u32, r: u32, p: u32) -> Result<Secret, String> {
    check_scrypt_params(log2n, r, p)?;
    let mut key = Secret(vec![0u8; 32]);
    // SAFETY: all pointers/lengths describe live buffers.
    let ok = unsafe {
        EVP_PBE_scrypt(
            pass.as_ptr().cast(),
            pass.len(),
            salt.as_ptr(),
            salt.len(),
            1u64 << log2n,
            u64::from(r),
            u64::from(p),
            MAXMEM,
            key.0.as_mut_ptr(),
            32,
        )
    };
    if ok != 1 {
        return Err("scrypt key derivation failed".into());
    }
    Ok(key)
}

struct Ctx(*mut c_void);
impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: freeing the context we created.
        unsafe { EVP_CIPHER_CTX_free(self.0) };
    }
}

pub fn check_passphrase(pass: &[u8]) -> Result<(), String> {
    let s =
        std::str::from_utf8(pass).map_err(|_| "the passphrase is not valid UTF-8".to_string())?;
    let n = s.chars().count();
    if n < MIN_PASSPHRASE_CHARS {
        return Err(format!(
            "the passphrase is {n} characters; at least {MIN_PASSPHRASE_CHARS} are required (the envelope is all that protects the key, and a short passphrase is offline work, not a barrier)"
        ));
    }
    Ok(())
}

pub fn encrypt(plain: &[u8], pass: &[u8]) -> Result<Vec<u8>, String> {
    check_passphrase(pass)?;
    let salt = random(SALT_LEN)?;
    let nonce = random(NONCE_LEN)?;
    seal_with(plain, pass, (LOG2_N, R, P), &salt, &nonce)
}

/// The envelope for given scrypt parameters (log2N, r, p), salt and nonce.
fn seal_with(
    plain: &[u8],
    pass: &[u8],
    (log2n, r, p): (u32, u32, u32),
    salt: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive(pass, salt, log2n, r, p)?;
    let mut header = MAGIC.to_vec();
    header.push(AEAD_AES256GCM);
    header.push(KDF_SCRYPT);
    for v in [log2n, r, p] {
        header.extend_from_slice(&v.to_be_bytes());
    }
    header.push(SALT_LEN as u8);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    debug_assert_eq!(header.len(), HEADER_LEN);
    // SAFETY: OpenSSL EVP calls on live buffers; return codes checked.
    unsafe {
        let ctx = Ctx(EVP_CIPHER_CTX_new());
        if ctx.0.is_null()
            || EVP_EncryptInit_ex(
                ctx.0,
                EVP_aes_256_gcm(),
                std::ptr::null_mut(),
                key.0.as_ptr(),
                nonce.as_ptr(),
            ) != 1
        {
            return Err("AES-256-GCM init failed".into());
        }
        let mut outl: c_int = 0;
        if EVP_EncryptUpdate(
            ctx.0,
            std::ptr::null_mut(),
            &mut outl,
            header.as_ptr(),
            header.len() as c_int,
        ) != 1
        {
            return Err("AES-256-GCM AAD failed".into());
        }
        let mut ct = vec![0u8; plain.len() + 16];
        if EVP_EncryptUpdate(
            ctx.0,
            ct.as_mut_ptr(),
            &mut outl,
            plain.as_ptr(),
            plain.len() as c_int,
        ) != 1
        {
            return Err("AES-256-GCM encrypt failed".into());
        }
        let mut total = outl as usize;
        if EVP_EncryptFinal_ex(ctx.0, ct.as_mut_ptr().add(total), &mut outl) != 1 {
            return Err("AES-256-GCM final failed".into());
        }
        total += outl as usize;
        ct.truncate(total);
        let mut tag = [0u8; TAG_LEN];
        if EVP_CIPHER_CTX_ctrl(
            ctx.0,
            EVP_CTRL_GCM_GET_TAG,
            TAG_LEN as c_int,
            tag.as_mut_ptr().cast(),
        ) != 1
        {
            return Err("AES-256-GCM tag failed".into());
        }
        let mut out = header;
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

pub fn is_envelope(data: &[u8]) -> bool {
    data.len() >= 6 && &data[..6] == MAGIC
}

pub fn decrypt(env: &[u8], pass: &[u8]) -> Result<Secret, String> {
    if env.len() < HEADER_LEN + TAG_LEN {
        return Err("envelope truncated".into());
    }
    if !is_envelope(env) {
        return Err("bad magic: not a HiddenForge encrypted key".into());
    }
    if env[6] != AEAD_AES256GCM {
        return Err(format!("unsupported cipher 0x{:02x}", env[6]));
    }
    if env[7] != KDF_SCRYPT {
        return Err(format!("unsupported KDF 0x{:02x}", env[7]));
    }
    let rd = |o: usize| u32::from_be_bytes([env[o], env[o + 1], env[o + 2], env[o + 3]]);
    let (log2n, r, p) = (rd(8), rd(12), rd(16));
    if !(12..=20).contains(&log2n) || !(1..=32).contains(&r) || !(1..=16).contains(&p) {
        return Err("refusing out-of-range scrypt parameters".into());
    }
    if usize::from(env[20]) != SALT_LEN {
        return Err("unexpected salt length".into());
    }
    let salt = &env[21..21 + SALT_LEN];
    let nonce = &env[21 + SALT_LEN..HEADER_LEN];
    let header = &env[..HEADER_LEN];
    let (ct, tag) = env[HEADER_LEN..].split_at(env.len() - HEADER_LEN - TAG_LEN);
    let key = derive(pass, salt, log2n, r, p)?;
    // SAFETY: OpenSSL EVP calls on live buffers; return codes checked.
    unsafe {
        let ctx = Ctx(EVP_CIPHER_CTX_new());
        if ctx.0.is_null()
            || EVP_DecryptInit_ex(
                ctx.0,
                EVP_aes_256_gcm(),
                std::ptr::null_mut(),
                key.0.as_ptr(),
                nonce.as_ptr(),
            ) != 1
        {
            return Err("AES-256-GCM init failed".into());
        }
        let mut outl: c_int = 0;
        if EVP_DecryptUpdate(
            ctx.0,
            std::ptr::null_mut(),
            &mut outl,
            header.as_ptr(),
            header.len() as c_int,
        ) != 1
        {
            return Err("AES-256-GCM AAD failed".into());
        }
        let mut pt = Secret(vec![0u8; ct.len() + 16]);
        if EVP_DecryptUpdate(
            ctx.0,
            pt.0.as_mut_ptr(),
            &mut outl,
            ct.as_ptr(),
            ct.len() as c_int,
        ) != 1
        {
            return Err("decryption failed".into());
        }
        let total = outl as usize;
        let mut tagb = [0u8; TAG_LEN];
        tagb.copy_from_slice(tag);
        if EVP_CIPHER_CTX_ctrl(
            ctx.0,
            EVP_CTRL_GCM_SET_TAG,
            TAG_LEN as c_int,
            tagb.as_mut_ptr().cast(),
        ) != 1
        {
            return Err("AES-256-GCM tag failed".into());
        }
        if EVP_DecryptFinal_ex(ctx.0, pt.0.as_mut_ptr().add(total), &mut outl) != 1 {
            return Err("decryption failed (wrong passphrase or a modified envelope)".into());
        }
        pt.0.truncate(total + outl as usize);
        Ok(pt)
    }
}

/// Read the passphrase file: trailing newline removed, size-capped.
pub fn read_passphrase(path: &str) -> Result<Secret, String> {
    let d = crate::fsops::read_small_regular_file(path, MAX_PASSPHRASE_BYTES)
        .map_err(|e| format!("cannot read the passphrase file {path}: {e}"))?;
    finish_passphrase(Secret(d))
}

/// The passphrase from stdin (`--passphrase-file -`): same rules, same cap.
pub fn read_passphrase_stdin() -> Result<Secret, String> {
    read_passphrase_from(std::io::stdin())
}

fn read_passphrase_from(r: impl std::io::Read) -> Result<Secret, String> {
    use std::io::Read;
    let mut d = Secret(Vec::new());
    if r.take(MAX_PASSPHRASE_BYTES as u64 + 1)
        .read_to_end(&mut d.0)
        .is_err()
        || d.0.len() > MAX_PASSPHRASE_BYTES
    {
        return Err(format!(
            "cannot read the passphrase from stdin (at most {MAX_PASSPHRASE_BYTES} bytes)"
        ));
    }
    finish_passphrase(d)
}

/// Strip the trailing newline(s) a file or a pipe adds, then apply the length rule.
fn finish_passphrase(mut d: Secret) -> Result<Secret, String> {
    while d.0.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        d.0.pop();
    }
    check_passphrase(&d.0)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsops::testtmp::Tmp;

    const PASS: &[u8] = b"correct horse battery staple";
    const KEY: &[u8] = b"== ed25519v1-secret: type0 ==\0\0\0secret-bytes-here";

    // Independent known answers, produced with Python (hashlib.scrypt for the
    // key, the `cryptography` package's AES-256-GCM with the 49-byte header as
    // additional data), salt = 00..0f, nonce = 64..6f, passphrase PASS.
    const SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const NONCE: [u8; 12] = [100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111];
    const KAT_PLAIN: &[u8] = b"== ed25519v1-secret: type0 ==\0\0\0KAT";
    const KAT_12_1_1: &str = "48464b45593102010000000c000000010000000110000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6f25df03eb6aa181993632a82a749b848f73bd79daa3c660467691ea4f4ce0a6ea2b53f451248a868834353b51dd27b15d31fe3d";
    const KAT_12_8_2: &str = "48464b45593102010000000c000000080000000210000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6fcc99bd5b88b2d7c76ffc04a28edb45f8eaa5bcdbd45fbe08fb1b08a31148263c3086368b9cf673ea9b36f6d000df0772b75813";
    const KAT_EMPTY: &str = "48464b45593102010000000c000000010000000110000102030405060708090a0b0c0d0e0f6465666768696a6b6c6d6e6f2110c3614b878cc4d354be5870aec26f";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A fast (N = 2^12) envelope with the known salt and nonce.
    fn fast_env() -> Vec<u8> {
        unhex(KAT_12_1_1)
    }

    /// `env` with the bytes at `at` replaced.
    fn with(env: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut v = env.to_vec();
        v[at..at + bytes.len()].copy_from_slice(bytes);
        v
    }

    const AUTH_FAILED: &str = "decryption failed (wrong passphrase or a modified envelope)";

    fn dec_err(env: &[u8]) -> String {
        match decrypt(env, PASS) {
            Ok(_) => panic!("decrypted"),
            Err(e) => e,
        }
    }

    #[test]
    fn roundtrip_and_tamper() {
        let env = encrypt(KEY, PASS).unwrap();
        assert!(is_envelope(&env));
        assert_eq!(decrypt(&env, PASS).unwrap().0, KEY.to_vec());
        assert!(decrypt(&env, b"wrong passphrase!!").is_err());
        for i in [0usize, 9, 30, 50, env.len() - 1] {
            let mut t = env.clone();
            t[i] ^= 1;
            assert!(decrypt(&t, PASS).is_err(), "tamper at {i} not detected");
        }
    }

    #[test]
    fn encrypt_matches_an_independent_implementation() {
        assert_eq!(
            seal_with(KAT_PLAIN, PASS, (12, 1, 1), &SALT, &NONCE).unwrap(),
            unhex(KAT_12_1_1)
        );
        assert_eq!(
            seal_with(KAT_PLAIN, PASS, (12, 8, 2), &SALT, &NONCE).unwrap(),
            unhex(KAT_12_8_2)
        );
        assert_eq!(
            seal_with(b"", PASS, (12, 1, 1), &SALT, &NONCE).unwrap(),
            unhex(KAT_EMPTY)
        );
    }

    #[test]
    fn decrypt_opens_an_independently_made_envelope() {
        assert_eq!(decrypt(&unhex(KAT_12_1_1), PASS).unwrap().0, KAT_PLAIN);
        assert_eq!(decrypt(&unhex(KAT_12_8_2), PASS).unwrap().0, KAT_PLAIN);
        let empty = decrypt(&unhex(KAT_EMPTY), PASS).unwrap();
        assert_eq!(empty.0, b"");
        assert_eq!(
            unhex(KAT_EMPTY).len(),
            HEADER_LEN + TAG_LEN,
            "the shortest valid envelope"
        );
        assert_eq!(
            dec_err_with(&unhex(KAT_12_1_1), b"another passphrase!!"),
            AUTH_FAILED
        );
    }

    fn dec_err_with(env: &[u8], pass: &[u8]) -> String {
        decrypt(env, pass).err().expect("decrypted")
    }

    #[test]
    fn encrypt_writes_the_documented_layout_with_fresh_salt_and_nonce() {
        let a = encrypt(KEY, PASS).unwrap();
        let b = encrypt(KEY, PASS).unwrap();
        assert_eq!(a.len(), HEADER_LEN + KEY.len() + TAG_LEN);
        // magic | aead 02 | kdf 01 | log2N=17 | r=8 | p=1 | salt_len=16
        assert_eq!(
            &a[..21],
            &unhex("48464b455931" /* HFKEY1 */)
                .into_iter()
                .chain([2, 1, 0, 0, 0, 17, 0, 0, 0, 8, 0, 0, 0, 1, 16])
                .collect::<Vec<u8>>()[..]
        );
        assert_ne!(a[21..37], b[21..37], "salt differs per envelope");
        assert_ne!(a[37..49], b[37..49], "nonce differs per envelope");
        assert_ne!(a[49..], b[49..]);
        assert_eq!(decrypt(&b, PASS).unwrap().0, KEY);
    }

    #[test]
    fn encrypt_refuses_a_short_passphrase_before_doing_any_work() {
        assert_eq!(
            encrypt(b"x", b"short").unwrap_err(),
            "the passphrase is 5 characters; at least 12 are required (the envelope is all that protects the key, and a short passphrase is offline work, not a barrier)"
        );
    }

    #[test]
    fn every_byte_of_an_envelope_is_authenticated() {
        let env = fast_env();
        for i in 0..env.len() {
            let mut t = env.clone();
            t[i] ^= 0x01;
            assert!(
                decrypt(&t, PASS).is_err(),
                "a change at byte {i} was accepted"
            );
        }
        assert!(decrypt(&env[..env.len() - 1], PASS).is_err());
        let mut longer = env.clone();
        longer.push(0);
        assert!(decrypt(&longer, PASS).is_err());
    }

    #[test]
    fn check_passphrase_counts_characters_not_bytes() {
        for ok in [
            "abcdefghijkl",
            "abcdefghijklm",
            &"é".repeat(12),
            "a b c d e f ",
            "            ",
        ] {
            assert_eq!(check_passphrase(ok.as_bytes()), Ok(()), "{ok:?}");
        }
        assert_eq!(
            check_passphrase(b"abcdefghijk").unwrap_err(),
            "the passphrase is 11 characters; at least 12 are required (the envelope is all that protects the key, and a short passphrase is offline work, not a barrier)"
        );
        // 22 bytes but 11 characters
        assert!(check_passphrase("é".repeat(11).as_bytes())
            .unwrap_err()
            .starts_with("the passphrase is 11 characters;"));
        assert!(check_passphrase(b"")
            .unwrap_err()
            .starts_with("the passphrase is 0 characters;"));
        assert_eq!(
            check_passphrase(b"abcdefghijk\xff\xfe").unwrap_err(),
            "the passphrase is not valid UTF-8"
        );
        assert_eq!(MIN_PASSPHRASE_CHARS, 12);
    }

    #[test]
    fn check_scrypt_params_follow_rfc_7914_and_the_memory_cap() {
        assert_eq!(
            check_scrypt_params(16, 1, 1).unwrap_err(),
            "refusing scrypt log2(N)=16 with r=1"
        );
        assert_eq!(check_scrypt_params(15, 1, 1), Ok(()));
        assert_eq!(check_scrypt_params(18, 2, 1), Ok(()));
        assert_eq!(check_scrypt_params(17, 8, 1), Ok(()));
        assert_eq!(check_scrypt_params(12, 1, 1), Ok(()));
        assert_eq!(check_scrypt_params(12, 1, 2_093_054), Ok(()));
        assert_eq!(
            check_scrypt_params(12, 1, 2_093_055).unwrap_err(),
            "refusing scrypt parameters needing 256 MiB"
        );
        assert_eq!(
            check_scrypt_params(18, 8, 1).unwrap_err(),
            "refusing scrypt parameters needing 256 MiB"
        );
        assert_eq!(
            check_scrypt_params(20, 8, 1).unwrap_err(),
            "refusing scrypt parameters needing 1024 MiB"
        );
        assert_eq!(
            check_scrypt_params(20, 1, 1).unwrap_err(),
            "refusing scrypt log2(N)=20 with r=1"
        );
        // the memory figure scales with r and with N, and p adds to it
        assert_eq!(
            check_scrypt_params(20, 2, 1).unwrap_err(),
            "refusing scrypt parameters needing 256 MiB"
        );
        assert_eq!(check_scrypt_params(19, 2, 1), Ok(()));
        assert_eq!(
            check_scrypt_params(17, 16, 100_000).unwrap_err(),
            "refusing scrypt parameters needing 451 MiB"
        );
        assert_eq!(
            check_scrypt_params(17, 16, 1).unwrap_err(),
            "refusing scrypt parameters needing 256 MiB"
        );
        assert_eq!(check_scrypt_params(16, 16, 1), Ok(()));
        // what this crate writes itself is accepted
        assert_eq!(check_scrypt_params(LOG2_N, R, P), Ok(()));
    }

    #[test]
    fn decrypt_rejects_malformed_envelopes_with_specific_messages() {
        let env = fast_env();
        assert_eq!(dec_err(&[]), "envelope truncated");
        assert_eq!(
            dec_err(&env[..HEADER_LEN + TAG_LEN - 1]),
            "envelope truncated"
        );
        assert_eq!(
            dec_err(&[0u8; HEADER_LEN + TAG_LEN - 1]),
            "envelope truncated"
        );
        // exactly the minimum length is looked at (and fails on the magic)
        assert_eq!(
            dec_err(&[0u8; HEADER_LEN + TAG_LEN]),
            "bad magic: not a HiddenForge encrypted key"
        );
        assert_eq!(
            dec_err(&with(&env, 5, b"2")),
            "bad magic: not a HiddenForge encrypted key"
        );
        assert_eq!(dec_err(&with(&env, 6, &[1])), "unsupported cipher 0x01");
        assert_eq!(dec_err(&with(&env, 6, &[0xab])), "unsupported cipher 0xab");
        assert_eq!(dec_err(&with(&env, 7, &[2])), "unsupported KDF 0x02");
        assert_eq!(dec_err(&with(&env, 7, &[0])), "unsupported KDF 0x00");
        assert_eq!(dec_err(&with(&env, 20, &[15])), "unexpected salt length");
        assert_eq!(dec_err(&with(&env, 20, &[17])), "unexpected salt length");
    }

    #[test]
    fn decrypt_range_checks_each_scrypt_parameter_at_its_edges() {
        let env = fast_env();
        let range = "refusing out-of-range scrypt parameters";
        let be = |v: u32| v.to_be_bytes();
        // log2N 12..=20 passes the range check (and then fails authentication,
        // since the header is part of the authenticated data); outside it does not
        assert_eq!(dec_err(&with(&env, 8, &be(11))), range);
        assert!(
            decrypt(&with(&env, 8, &be(12)), PASS).is_ok(),
            "12 is the edge"
        );
        assert_eq!(dec_err(&with(&env, 8, &be(13))), AUTH_FAILED);
        // 20 is inside the range; derive then refuses it for r=1 (RFC 7914)
        assert_eq!(
            dec_err(&with(&env, 8, &be(20))),
            "refusing scrypt log2(N)=20 with r=1"
        );
        assert_eq!(dec_err(&with(&env, 8, &be(21))), range);
        assert_eq!(dec_err(&with(&env, 8, &be(0))), range);
        // r 1..=32
        assert_eq!(dec_err(&with(&env, 12, &be(0))), range);
        assert_eq!(dec_err(&with(&env, 12, &be(2))), AUTH_FAILED);
        assert_eq!(dec_err(&with(&env, 12, &be(32))), AUTH_FAILED);
        assert_eq!(dec_err(&with(&env, 12, &be(33))), range);
        // p 1..=16
        assert_eq!(dec_err(&with(&env, 16, &be(0))), range);
        assert_eq!(dec_err(&with(&env, 16, &be(16))), AUTH_FAILED);
        assert_eq!(dec_err(&with(&env, 16, &be(17))), range);
        // every byte of each big-endian field counts, not just the last
        for at in [8usize, 12, 16] {
            for hi in 0..3 {
                let mut field = if at == 8 { be(12) } else { be(1) };
                field[hi] = 1;
                assert_eq!(
                    dec_err(&with(&env, at, &field)),
                    range,
                    "field at {at}, byte {hi}"
                );
            }
        }
        // in range for the format but refused by the memory rule in derive
        assert_eq!(
            dec_err(&with(&with(&env, 8, &be(20)), 12, &be(8))),
            "refusing scrypt parameters needing 1024 MiB"
        );
        assert_eq!(
            dec_err(&with(&with(&env, 8, &be(19)), 12, &be(2))),
            AUTH_FAILED,
            "128 MiB is inside the cap"
        );
    }

    #[test]
    fn is_envelope_needs_the_whole_magic() {
        assert!(is_envelope(b"HFKEY1"));
        assert!(is_envelope(b"HFKEY1 and then anything"));
        assert!(is_envelope(&fast_env()));
        for no in [
            &b""[..],
            b"H",
            b"HFKEY",
            b"HFKEY2",
            b"hfkey1",
            b" HFKEY1",
            b"XFKEY1",
            b"HFKEY\x001",
        ] {
            assert!(!is_envelope(no), "{no:?}");
        }
    }

    #[test]
    fn finish_passphrase_trims_only_trailing_line_endings() {
        let twelve = "abcdefghijkl";
        for (input, want) in [
            (format!("{twelve}\n"), twelve.to_string()),
            (format!("{twelve}\r\n"), twelve.to_string()),
            (format!("{twelve}\n\n\r\n"), twelve.to_string()),
            (format!("{twelve}\r"), twelve.to_string()),
            (format!("{twelve}\r\r"), twelve.to_string()),
            (twelve.to_string(), twelve.to_string()),
            (format!("{twelve} "), format!("{twelve} ")),
            (format!("{twelve}\t"), format!("{twelve}\t")),
            (format!("{twelve}\n "), format!("{twelve}\n ")),
            ("abcdef\nghijkl\n".to_string(), "abcdef\nghijkl".to_string()),
            ("\nabcdefghijkl".to_string(), "\nabcdefghijkl".to_string()),
        ] {
            let got = finish_passphrase(Secret(input.clone().into_bytes())).unwrap();
            assert_eq!(got.0, want.as_bytes(), "{input:?}");
        }
        // trimming happens before the length rule
        for short in ["abcdefghijk\n", "abcdefghijk\r\n", "\n\n\n", "\r", ""] {
            assert!(
                finish_passphrase(Secret(short.as_bytes().to_vec()))
                    .err()
                    .is_some_and(|e| e.starts_with("the passphrase is ")),
                "{short:?}"
            );
        }
        assert_eq!(
            finish_passphrase(Secret(b"abcdefghijk\n".to_vec())).err().unwrap(),
            "the passphrase is 11 characters; at least 12 are required (the envelope is all that protects the key, and a short passphrase is offline work, not a barrier)"
        );
        assert_eq!(
            finish_passphrase(Secret(b"abcdefghijk\xff\n".to_vec()))
                .err()
                .unwrap(),
            "the passphrase is not valid UTF-8"
        );
    }

    struct FailingRead;
    impl std::io::Read for FailingRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

    #[test]
    fn stdin_passphrase_is_capped_at_4096_bytes_before_trimming() {
        let cap_msg = "cannot read the passphrase from stdin (at most 4096 bytes)";
        let p = |b: Vec<u8>| read_passphrase_from(std::io::Cursor::new(b));
        assert_eq!(p(vec![b'a'; 4096]).unwrap().0, vec![b'a'; 4096]);
        assert_eq!(p(vec![b'a'; 4097]).err().unwrap(), cap_msg);
        assert_eq!(p(vec![b'a'; 100_000]).err().unwrap(), cap_msg);
        // the newline counts toward the cap, and is then trimmed
        let mut with_nl = vec![b'a'; 4095];
        with_nl.push(b'\n');
        assert_eq!(p(with_nl).unwrap().0, vec![b'a'; 4095]);
        let mut over = vec![b'a'; 4096];
        over.push(b'\n');
        assert_eq!(p(over).err().unwrap(), cap_msg);
        // a read error is reported the same way, even with nothing read yet
        assert_eq!(read_passphrase_from(FailingRead).err().unwrap(), cap_msg);
        // newline handling and the length rule apply to stdin too
        assert_eq!(p(b"abcdefghijkl\r\n".to_vec()).unwrap().0, b"abcdefghijkl");
        assert!(p(b"short\n".to_vec())
            .err()
            .unwrap()
            .starts_with("the passphrase is 5 characters;"));
        assert!(p(Vec::new())
            .err()
            .unwrap()
            .starts_with("the passphrase is 0 characters;"));
    }

    #[test]
    fn passphrase_file_is_read_capped_and_trimmed() {
        let d = Tmp::new("kcpass");
        let f = format!("{d}/pass");
        std::fs::write(&f, b"correct horse battery\r\n").unwrap();
        assert_eq!(read_passphrase(&f).unwrap().0, b"correct horse battery");
        std::fs::write(&f, b"correct horse battery\n\n").unwrap();
        assert_eq!(read_passphrase(&f).unwrap().0, b"correct horse battery");
        std::fs::write(&f, b"x\n").unwrap();
        assert!(read_passphrase(&f)
            .err()
            .unwrap()
            .starts_with("the passphrase is 1 characters;"));
        std::fs::write(&f, vec![b'a'; 4096]).unwrap();
        assert_eq!(read_passphrase(&f).unwrap().0.len(), 4096);
        std::fs::write(&f, vec![b'a'; 4097]).unwrap();
        assert_eq!(
            read_passphrase(&f).err().unwrap(),
            format!(
                "cannot read the passphrase file {f}: [Errno 27] {f} is larger than 4096 bytes"
            )
        );
        let missing = format!("{d}/none");
        assert_eq!(
            read_passphrase(&missing).err().unwrap(),
            format!("cannot read the passphrase file {missing}: [Errno 2] No such file or directory: '{missing}'")
        );
    }

    // ---- zeroizing --------------------------------------------------------

    mod spy {
        //! Test allocator: when armed with a pointer, reports whether the
        //! first `LEN` bytes were all zero at the moment that block is freed.
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        pub static WATCH: AtomicUsize = AtomicUsize::new(0);
        pub static LEN: AtomicUsize = AtomicUsize::new(0);
        /// 0 = not seen, 1 = all zero when freed, 2 = not zero when freed
        pub static RESULT: AtomicUsize = AtomicUsize::new(0);

        pub struct Spy;

        // SAFETY: every call is forwarded to the system allocator unchanged;
        // the only addition is a read of the block before it is freed.
        unsafe impl GlobalAlloc for Spy {
            unsafe fn alloc(&self, l: Layout) -> *mut u8 {
                unsafe { System.alloc(l) }
            }
            unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
                let w = WATCH.load(SeqCst);
                if w != 0 && p as usize == w {
                    let n = l.size().min(LEN.load(SeqCst));
                    // SAFETY: the block is still live until System.dealloc below.
                    let s = unsafe { std::slice::from_raw_parts(p, n) };
                    RESULT.store(if s.iter().all(|b| *b == 0) { 1 } else { 2 }, SeqCst);
                    WATCH.store(0, SeqCst);
                }
                unsafe { System.dealloc(p, l) }
            }
        }

        #[global_allocator]
        static A: Spy = Spy;
    }

    fn zero_at_free(v: Vec<u8>, drop_it: impl FnOnce(Vec<u8>)) -> usize {
        use std::sync::atomic::Ordering::SeqCst;
        spy::RESULT.store(0, SeqCst);
        spy::LEN.store(v.len(), SeqCst);
        spy::WATCH.store(v.as_ptr() as usize, SeqCst);
        drop_it(v);
        spy::RESULT.load(SeqCst)
    }

    #[test]
    fn secret_is_zeroed_before_its_memory_is_freed() {
        // control: an ordinary Vec still holds its bytes when freed, so the spy sees them
        assert_eq!(zero_at_free(vec![0xAB; 64], drop), 2);
        assert_eq!(zero_at_free(vec![0xAB; 64], |v| drop(Secret(v))), 1);
    }

    #[test]
    fn decrypted_keys_are_zeroed_when_dropped() {
        let s = decrypt(&fast_env(), PASS).unwrap();
        assert_eq!(s.0, KAT_PLAIN);
        let (ptr, len) = (s.0.as_ptr() as usize, s.0.len());
        use std::sync::atomic::Ordering::SeqCst;
        spy::RESULT.store(0, SeqCst);
        spy::LEN.store(len, SeqCst);
        spy::WATCH.store(ptr, SeqCst);
        drop(s);
        assert_eq!(spy::RESULT.load(SeqCst), 1);
    }
}
