//! Sealed keys (opt-in, HIDDENFORGE_KEY_PASSPHRASE_FILE): the volume keeps
//! `hs_ed25519_secret_key.enc` (a keycrypt envelope), the public key and the
//! hostname; Tor's HiddenServiceDir moves to the tmpfs, /var/lib/tor/hs-ram/<name>,
//! where the secret key is decrypted at every start.
//!
//! What this protects: the volume, a disk or a backup taken while the service
//! is not running, provided the passphrase is not stored beside it. What it does
//! not protect: a running host (the key is in memory there), or a passphrase
//! file on the same disk. Overwriting a migrated plaintext key cannot reach
//! blocks a copy-on-write filesystem or an SSD kept elsewhere; the docs say so.
//!
//! Every function here runs as the tor user (a helper the supervisor starts,
//! or the supervisor itself in no-root mode), so it never needs root's
//! DAC_OVERRIDE to reach the tor-owned directories.

use crate::fsops;
use crate::keycrypt::{self, Secret};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

pub const ENV: &str = "HIDDENFORGE_KEY_PASSPHRASE_FILE";
pub const RAM: &str = "/var/lib/tor/hs-ram";
pub const KEYS: &str = "/var/lib/tor/hidden_service";
const SECRET: &str = "hs_ed25519_secret_key";
const SEALED: &str = "hs_ed25519_secret_key.enc";
const PUBLIC: &str = "hs_ed25519_public_key";
const HOSTNAME: &str = "hostname";

pub fn passphrase_file() -> Option<String> {
    std::env::var(ENV).ok().filter(|v| !v.is_empty())
}

fn read(path: &str, max: usize) -> Option<Vec<u8>> {
    fsops::read_small_regular_file(path, max).ok()
}

/// Write a file atomically (new O_EXCL temp, fsync, rename), mode `mode`.
fn write_atomic(dir: &str, name: &str, data: &[u8], mode: u32) -> Result<(), String> {
    let tmp = format!("{dir}/.{name}.{}.tmp", std::process::id());
    let _ = std::fs::remove_file(&tmp);
    let r = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, format!("{dir}/{name}"))?;
        // Make the rename durable too.
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|e| format!("cannot write {dir}/{name}: {e}"))
}

/// Overwrite a plaintext key in place, flush it, then remove it.
fn wipe(path: &str) -> Result<(), String> {
    let st = fsops::lstat(path).map_err(|e| e.msg)?;
    if !fsops::is_type(&st, libc::S_IFREG) || st.st_nlink != 1 {
        return Err(format!(
            "{path} is not a single regular file; refusing to overwrite it"
        ));
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(&vec![0u8; st.st_size as usize])
        .map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::remove_file(path).map_err(|e| e.to_string())
}

fn copy_if_present(from_dir: &str, to_dir: &str, name: &str, mode: u32) -> Result<(), String> {
    if let Some(d) = read(&format!("{from_dir}/{name}"), 8192) {
        if read(&format!("{to_dir}/{name}"), 8192).as_deref() != Some(d.as_slice()) {
            write_atomic(to_dir, name, &d, mode)?;
        }
    }
    Ok(())
}

/// Before Tor starts: put the decrypted key in RAM. Returns a line to log, if any.
pub fn unseal(name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    let vol = format!("{KEYS}/{name}");
    let ram = format!("{RAM}/{name}");
    let mut note = None;
    let secret: Option<Secret> = if let Some(env) = read(&format!("{vol}/{SEALED}"), 8192) {
        Some(keycrypt::decrypt(&env, pass).map_err(|e| format!("{name}: {e}"))?)
    } else if let Some(plain) = read(&format!("{vol}/{SECRET}"), 8192) {
        // Migration of an existing plaintext key: seal, prove the seal opens to
        // the same bytes, and only then remove the plaintext.
        let plain = Secret(plain);
        let env = keycrypt::encrypt(&plain.0, pass)?;
        write_atomic(&vol, SEALED, &env, 0o600)?;
        let back = read(&format!("{vol}/{SEALED}"), 8192)
            .ok_or("the sealed key could not be read back")?;
        if keycrypt::decrypt(&back, pass)?.0 != plain.0 {
            return Err(format!("{name}: the sealed key did not decrypt to the original; the plaintext key was left in place"));
        }
        wipe(&format!("{vol}/{SECRET}"))?;
        note = Some(format!(
            "Sealed the key for {name}: it is now encrypted at rest ({SEALED}); the plaintext copy on the volume was overwritten and removed."
        ));
        Some(plain)
    } else {
        None // a new service: Tor generates the key in RAM, seal_new() stores it
    };
    if let Some(s) = secret {
        write_atomic(&ram, SECRET, &s.0, 0o600)?;
    }
    copy_if_present(&vol, &ram, PUBLIC, 0o600)?;
    copy_if_present(&vol, &ram, HOSTNAME, 0o600)?;
    Ok(note)
}

/// While Tor runs: seal a newly generated key, and keep the volume's public key
/// and hostname current. Returns a line to log when something was sealed.
pub fn seal_new(name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    let vol = format!("{KEYS}/{name}");
    let ram = format!("{RAM}/{name}");
    let mut note = None;
    if read(&format!("{vol}/{SEALED}"), 8192).is_none() {
        if let Some(plain) = read(&format!("{ram}/{SECRET}"), 8192) {
            let plain = Secret(plain);
            let env = keycrypt::encrypt(&plain.0, pass)?;
            write_atomic(&vol, SEALED, &env, 0o600)?;
            note = Some(format!("Sealed the new key for {name} at rest ({SEALED})."));
        }
    }
    copy_if_present(&ram, &vol, PUBLIC, 0o600)?;
    copy_if_present(&ram, &vol, HOSTNAME, 0o600)?;
    Ok(note)
}

/// True once the volume holds a sealed key and the current hostname.
pub fn settled(name: &str) -> bool {
    let vol = format!("{KEYS}/{name}");
    let ram = format!("{RAM}/{name}");
    read(&format!("{vol}/{SEALED}"), 8192).is_some()
        && read(&format!("{ram}/{HOSTNAME}"), 256).is_some()
        && read(&format!("{ram}/{HOSTNAME}"), 256) == read(&format!("{vol}/{HOSTNAME}"), 256)
}

/// `hiddenforge __keys unseal|seal <name>`, passphrase on stdin (from the supervisor).
pub fn helper(op: &str, name: &str) -> i32 {
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || name.is_empty()
    {
        return 2;
    }
    let mut buf = Vec::new();
    use std::io::Read;
    if std::io::stdin().take(4097).read_to_end(&mut buf).is_err() || buf.len() > 4096 {
        return 2;
    }
    let pass = Secret(buf);
    let r = match op {
        "unseal" => unseal(name, &pass.0),
        "seal" => seal_new(name, &pass.0),
        _ => return 2,
    };
    match r {
        Ok(Some(note)) => {
            println!("{note}");
            0
        }
        Ok(None) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
