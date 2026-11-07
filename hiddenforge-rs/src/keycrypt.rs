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

fn derive(pass: &[u8], salt: &[u8], log2n: u32, r: u32, p: u32) -> Result<Secret, String> {
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
    let key = derive(pass, &salt, LOG2_N, R, P)?;
    let mut header = MAGIC.to_vec();
    header.push(AEAD_AES256GCM);
    header.push(KDF_SCRYPT);
    for v in [LOG2_N, R, P] {
        header.extend_from_slice(&v.to_be_bytes());
    }
    header.push(SALT_LEN as u8);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
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
    let d = crate::fsops::read_small_regular_file(path, 4096)
        .map_err(|e| format!("cannot read the passphrase file {path}: {e}"))?;
    let mut d = Secret(d);
    while d.0.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        d.0.pop();
    }
    check_passphrase(&d.0)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let pass = b"correct horse battery staple";
        let key = b"== ed25519v1-secret: type0 ==\0\0\0secret-bytes-here";
        let env = encrypt(key, pass).unwrap();
        assert!(is_envelope(&env));
        assert_eq!(decrypt(&env, pass).unwrap().0, key.to_vec());
        assert!(decrypt(&env, b"wrong passphrase!!").is_err());
        for i in [0usize, 9, 30, 50, env.len() - 1] {
            let mut t = env.clone();
            t[i] ^= 1;
            assert!(decrypt(&t, pass).is_err(), "tamper at {i} not detected");
        }
    }

    #[test]
    fn short_passphrase_refused() {
        assert!(encrypt(b"x", b"short").is_err());
    }
}
