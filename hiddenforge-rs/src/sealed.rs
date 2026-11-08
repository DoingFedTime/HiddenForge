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
const AUTH_DIR: &str = "authorized_clients";

pub fn passphrase_file() -> Option<String> {
    passphrase_file_from(std::env::var(ENV).ok())
}

/// An unset or empty variable means key sealing is off.
fn passphrase_file_from(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
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
    unseal_at(KEYS, RAM, name, pass)
}

fn unseal_at(keys: &str, ramroot: &str, name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    let vol = format!("{keys}/{name}");
    let ram = format!("{ramroot}/{name}");
    let mut note = None;
    let secret: Option<Secret> = if let Some(env) = read(&format!("{vol}/{SEALED}"), 8192) {
        let s = keycrypt::decrypt(&env, pass).map_err(|e| format!("{name}: {e}"))?;
        // A plaintext key beside the envelope means a migration was interrupted after the
        // envelope was written (a crash, a failed wipe). Left alone it would stay on the
        // volume for good, since this branch is taken on every later start. Same bytes:
        // finish the migration. Different bytes: two identities, so refuse to pick one.
        match read(&format!("{vol}/{SECRET}"), 8192) {
            Some(p) if p == s.0 => {
                wipe(&format!("{vol}/{SECRET}"))?;
                note = Some(format!(
                    "{name}: finished an interrupted migration: the plaintext key left on the volume matched {SEALED} and was overwritten and removed."
                ));
            }
            Some(_) => {
                return Err(format!(
                    "{name}: {SECRET} is still on the volume and differs from the sealed key ({SEALED}); refusing to start with two identities. Remove the one that is wrong."
                ))
            }
            None => {}
        }
        Some(s)
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
    sync_authorized_clients(&vol, &ram)?;
    Ok(note)
}

/// Client authorization lives on the volume (`authorized_clients/*.auth`, public
/// keys only), but Tor reads it from its HiddenServiceDir, which here is the RAM
/// copy: mirror it exactly, so a client removed from the volume loses access too.
fn sync_authorized_clients(vol: &str, ram: &str) -> Result<(), String> {
    let (from, to) = (format!("{vol}/{AUTH_DIR}"), format!("{ram}/{AUTH_DIR}"));
    let wanted: Vec<String> = match std::fs::read_dir(&from) {
        Ok(rd) => rd
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| {
                n.strip_suffix(".auth")
                    .is_some_and(crate::clientauth::client_name_ok)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    if wanted.is_empty() && fsops::lstat(&to).is_err() {
        return Ok(());
    }
    if fsops::lstat(&to).is_err() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&to)
            .map_err(|e| format!("cannot create {to}: {e}"))?;
    }
    for n in &wanted {
        copy_if_present(&from, &to, n, 0o600)?;
    }
    if let Ok(rd) = std::fs::read_dir(&to) {
        for e in rd.flatten() {
            if let Some(n) = e.file_name().to_str() {
                if !wanted.iter().any(|w| w == n) {
                    std::fs::remove_file(format!("{to}/{n}"))
                        .map_err(|err| format!("cannot remove {to}/{n}: {err}"))?;
                }
            }
        }
    }
    Ok(())
}

/// While Tor runs: seal a newly generated key, and keep the volume's public key
/// and hostname current. Returns a line to log when something was sealed.
pub fn seal_new(name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    seal_new_at(KEYS, RAM, name, pass)
}

fn seal_new_at(
    keys: &str,
    ramroot: &str,
    name: &str,
    pass: &[u8],
) -> Result<Option<String>, String> {
    let vol = format!("{keys}/{name}");
    let ram = format!("{ramroot}/{name}");
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
    settled_at(KEYS, RAM, name)
}

fn settled_at(keys: &str, ramroot: &str, name: &str) -> bool {
    let vol = format!("{keys}/{name}");
    let ram = format!("{ramroot}/{name}");
    read(&format!("{vol}/{SEALED}"), 8192).is_some()
        && read(&format!("{ram}/{HOSTNAME}"), 256).is_some()
        && read(&format!("{ram}/{HOSTNAME}"), 256) == read(&format!("{vol}/{HOSTNAME}"), 256)
}

/// Turn encryption at rest off for one service (`hiddenforge unseal-keys`):
/// put the plaintext key back on the volume, prove it is the sealed key's
/// content, and only then remove the envelope. Run with the service stopped.
/// Ok(None) when the service has no sealed key (nothing to do).
pub fn unseal_to_volume(name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    unseal_in(KEYS, name, pass)
}

fn unseal_in(keys: &str, name: &str, pass: &[u8]) -> Result<Option<String>, String> {
    let vol = format!("{keys}/{name}");
    let Some(env) = read(&format!("{vol}/{SEALED}"), 8192) else {
        return Ok(None);
    };
    let plain = keycrypt::decrypt(&env, pass).map_err(|e| format!("{name}: {e}"))?;
    match read(&format!("{vol}/{SECRET}"), 8192) {
        Some(existing) if existing != plain.0 => {
            return Err(format!(
                "{name}: {SECRET} exists and differs from the sealed key; refusing to choose between them"
            ))
        }
        Some(_) => {}
        None => write_atomic(&vol, SECRET, &plain.0, 0o600)?,
    }
    if read(&format!("{vol}/{SECRET}"), 8192).as_deref() != Some(plain.0.as_slice()) {
        return Err(format!(
            "{name}: the plaintext key did not read back intact; the sealed key was left in place"
        ));
    }
    std::fs::remove_file(format!("{vol}/{SEALED}"))
        .map_err(|e| format!("{name}: cannot remove {SEALED}: {e}"))?;
    if let Ok(d) = std::fs::File::open(&vol) {
        let _ = d.sync_all();
    }
    Ok(Some(format!(
        "{name}: the key is plaintext on the volume again ({SECRET}); {SEALED} removed"
    )))
}

/// `hiddenforge __keys unseal|seal <name>`, passphrase on stdin (from the supervisor).
pub fn helper(op: &str, name: &str) -> i32 {
    helper_at(
        (KEYS, RAM),
        op,
        name,
        std::io::stdin(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// The helper with its volume roots, input and output injected. Exit codes: 0 done
/// (a note, if any, on `out`), 1 the operation failed (its message on `err`),
/// 2 bad arguments or an unreadable or oversized passphrase.
fn helper_at(
    (keys, ramroot): (&str, &str),
    op: &str,
    name: &str,
    input: impl std::io::Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || name.is_empty()
    {
        return 2;
    }
    let mut buf = Vec::new();
    use std::io::Read;
    if input.take(4097).read_to_end(&mut buf).is_err() || buf.len() > 4096 {
        return 2;
    }
    let pass = Secret(buf);
    let r = match op {
        "unseal" => unseal_at(keys, ramroot, name, &pass.0),
        "seal" => seal_new_at(keys, ramroot, name, &pass.0),
        _ => return 2,
    };
    match r {
        Ok(Some(note)) => {
            let _ = writeln!(out, "{note}");
            0
        }
        Ok(None) => 0,
        Err(e) => {
            let _ = writeln!(err, "{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsops::testtmp::Tmp;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const PASS: &[u8] = b"correct horse battery staple";
    const KEY: &[u8] =
        b"== ed25519v1-secret: type0 ==\0\0\0 sixty-four bytes of secret key, give or take";
    const WRONG: &[u8] = b"the wrong passphrase!";
    const AUTH_FAILED: &str = "decryption failed (wrong passphrase or a modified envelope)";

    /// One envelope for KEY, made once: scrypt at the production cost is the slow part.
    fn envelope() -> Vec<u8> {
        static ENV: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        ENV.get_or_init(|| keycrypt::encrypt(KEY, PASS).unwrap())
            .clone()
    }

    /// A key volume and a RAM root, each with a "myapp" service directory.
    struct Layout {
        keys: Tmp,
        ram: Tmp,
        vol: String,
        rdir: String,
    }

    fn layout(tag: &str) -> Layout {
        let (keys, ram) = (Tmp::new(tag), Tmp::new(&format!("{tag}-ram")));
        let (vol, rdir) = (format!("{keys}/myapp"), format!("{ram}/myapp"));
        std::fs::create_dir(&vol).unwrap();
        std::fs::create_dir(&rdir).unwrap();
        Layout {
            keys,
            ram,
            vol,
            rdir,
        }
    }

    fn mode_of(p: &str) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn exists(p: &str) -> bool {
        std::fs::symlink_metadata(p).is_ok()
    }

    fn chmod(p: &str, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn not_root() -> bool {
        !crate::privs::is_root()
    }

    // ---- unseal / migration ------------------------------------------------

    /// A migration interrupted after the envelope was written (crash, failed wipe) must not
    /// leave the plaintext key on the volume for good: the next start finishes the job.
    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_finishes_an_interrupted_migration() {
        let l = layout("interrupted");
        std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
        std::fs::write(format!("{}/{SECRET}", l.vol), KEY).unwrap(); // the leftover plaintext
        let note = unseal_at(&l.keys, &l.ram, "myapp", PASS).unwrap();
        assert!(
            !exists(&format!("{}/{SECRET}", l.vol)),
            "the plaintext key is removed from the volume"
        );
        assert_eq!(
            note.as_deref(),
            Some("myapp: finished an interrupted migration: the plaintext key left on the volume matched hs_ed25519_secret_key.enc and was overwritten and removed.")
        );
        assert_eq!(std::fs::read(format!("{}/{SECRET}", l.rdir)).unwrap(), KEY);
        assert!(exists(&format!("{}/{SEALED}", l.vol)), "the envelope stays");
    }

    /// A plaintext key that DIFFERS from the sealed one is a second identity: refuse,
    /// change nothing, and say why.
    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_refuses_a_different_leftover_plaintext() {
        let l = layout("twokeys");
        std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
        std::fs::write(format!("{}/{SECRET}", l.vol), b"some other secret key").unwrap();
        let err = unseal_at(&l.keys, &l.ram, "myapp", PASS).unwrap_err();
        assert_eq!(
            err,
            "myapp: hs_ed25519_secret_key is still on the volume and differs from the sealed key (hs_ed25519_secret_key.enc); refusing to start with two identities. Remove the one that is wrong."
        );
        assert_eq!(
            std::fs::read(format!("{}/{SECRET}", l.vol)).unwrap(),
            b"some other secret key"
        );
        assert!(!exists(&format!("{}/{SECRET}", l.rdir)), "nothing unsealed");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_puts_the_key_and_public_files_in_ram_and_leaves_the_volume_alone() {
        let l = layout("unseal");
        std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
        std::fs::write(format!("{}/{PUBLIC}", l.vol), b"public bytes").unwrap();
        std::fs::write(format!("{}/{HOSTNAME}", l.vol), b"x.onion\n").unwrap();
        assert_eq!(unseal_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        let secret = format!("{}/{SECRET}", l.rdir);
        assert_eq!(std::fs::read(&secret).unwrap(), KEY);
        assert_eq!(mode_of(&secret), 0o600);
        for (n, want) in [
            (PUBLIC, &b"public bytes"[..]),
            (HOSTNAME, &b"x.onion\n"[..]),
        ] {
            let f = format!("{}/{n}", l.rdir);
            assert_eq!(
                (std::fs::read(&f).unwrap(), mode_of(&f)),
                (want.to_vec(), 0o600)
            );
        }
        assert!(
            !exists(&format!("{}/{SECRET}", l.vol)),
            "no plaintext on the volume"
        );
        assert_eq!(
            std::fs::read(format!("{}/{SEALED}", l.vol)).unwrap(),
            envelope()
        );
        // a second start changes nothing
        assert_eq!(unseal_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        assert_eq!(std::fs::read(&secret).unwrap(), KEY);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_with_the_wrong_passphrase_fails_and_writes_nothing() {
        let l = layout("wrongpass");
        std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
        std::fs::write(format!("{}/{PUBLIC}", l.vol), b"p").unwrap();
        assert_eq!(
            unseal_at(&l.keys, &l.ram, "myapp", WRONG),
            Err(format!("myapp: {AUTH_FAILED}"))
        );
        assert_eq!(std::fs::read_dir(&l.rdir).unwrap().count(), 0);
        assert_eq!(
            std::fs::read(format!("{}/{SEALED}", l.vol)).unwrap(),
            envelope()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_for_a_new_service_only_mirrors_public_files() {
        let l = layout("newsvc");
        std::fs::write(format!("{}/{HOSTNAME}", l.vol), b"h.onion\n").unwrap();
        assert_eq!(unseal_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        assert!(!exists(&format!("{}/{SECRET}", l.rdir)));
        assert_eq!(
            std::fs::read(format!("{}/{HOSTNAME}", l.rdir)).unwrap(),
            b"h.onion\n"
        );
        assert!(
            !exists(&format!("{}/{SEALED}", l.vol)),
            "nothing is sealed here"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_migrates_a_plaintext_key_and_removes_it() {
        let l = layout("migrate");
        std::fs::write(format!("{}/{SECRET}", l.vol), KEY).unwrap();
        let note = unseal_at(&l.keys, &l.ram, "myapp", PASS).unwrap();
        assert_eq!(
            note.as_deref(),
            Some("Sealed the key for myapp: it is now encrypted at rest (hs_ed25519_secret_key.enc); the plaintext copy on the volume was overwritten and removed.")
        );
        assert!(!exists(&format!("{}/{SECRET}", l.vol)));
        let sealed = format!("{}/{SEALED}", l.vol);
        assert_eq!(mode_of(&sealed), 0o600);
        assert_eq!(
            keycrypt::decrypt(&std::fs::read(&sealed).unwrap(), PASS)
                .unwrap()
                .0,
            KEY
        );
        assert_eq!(std::fs::read(format!("{}/{SECRET}", l.rdir)).unwrap(), KEY);
        // and the next start takes the sealed path with no note
        assert_eq!(unseal_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn migration_with_a_short_passphrase_leaves_the_plaintext_alone() {
        let l = layout("migshort");
        std::fs::write(format!("{}/{SECRET}", l.vol), KEY).unwrap();
        let e = unseal_at(&l.keys, &l.ram, "myapp", b"short").unwrap_err();
        assert!(e.starts_with("the passphrase is 5 characters;"), "{e}");
        assert_eq!(std::fs::read(format!("{}/{SECRET}", l.vol)).unwrap(), KEY);
        assert!(!exists(&format!("{}/{SEALED}", l.vol)));
        assert!(!exists(&format!("{}/{SECRET}", l.rdir)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_in_restores_the_key_and_removes_the_envelope() {
        let l = layout("ok");
        let (keys, vol) = (&*l.keys, &l.vol);
        assert_eq!(
            unseal_in(keys, "myapp", PASS),
            Ok(None),
            "no envelope: nothing to do"
        );
        std::fs::write(format!("{vol}/{SEALED}"), envelope()).unwrap();
        assert_eq!(
            unseal_in(keys, "myapp", PASS),
            Ok(Some("myapp: the key is plaintext on the volume again (hs_ed25519_secret_key); hs_ed25519_secret_key.enc removed".to_string()))
        );
        assert_eq!(std::fs::read(format!("{vol}/{SECRET}")).unwrap(), KEY);
        assert_eq!(mode_of(&format!("{vol}/{SECRET}")), 0o600);
        assert!(!exists(&format!("{vol}/{SEALED}")), "the envelope is gone");
        assert_eq!(
            unseal_in(keys, "myapp", PASS),
            Ok(None),
            "nothing left to do"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn unseal_in_refuses_a_conflicting_plaintext_and_a_wrong_passphrase() {
        let l = layout("conflict");
        let (keys, vol) = (&*l.keys, &l.vol);
        std::fs::write(format!("{vol}/{SEALED}"), envelope()).unwrap();
        assert_eq!(
            unseal_in(keys, "myapp", WRONG),
            Err(format!("myapp: {AUTH_FAILED}"))
        );
        assert!(
            exists(&format!("{vol}/{SEALED}")),
            "kept after a wrong passphrase"
        );
        assert!(!exists(&format!("{vol}/{SECRET}")), "no plaintext written");
        std::fs::write(format!("{vol}/{SECRET}"), b"a different key").unwrap();
        assert_eq!(
            unseal_in(keys, "myapp", PASS),
            Err("myapp: hs_ed25519_secret_key exists and differs from the sealed key; refusing to choose between them".to_string())
        );
        assert!(
            exists(&format!("{vol}/{SEALED}")),
            "nothing removed on a conflict"
        );
        assert_eq!(
            std::fs::read(format!("{vol}/{SECRET}")).unwrap(),
            b"a different key"
        );
        // The same plaintext already present is fine: the envelope goes, the key stays.
        std::fs::write(format!("{vol}/{SECRET}"), KEY).unwrap();
        assert!(unseal_in(keys, "myapp", PASS).unwrap().is_some());
        assert_eq!(std::fs::read(format!("{vol}/{SECRET}")).unwrap(), KEY);
        assert!(!exists(&format!("{vol}/{SEALED}")));
    }

    // ---- seal_new / settled -----------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn seal_new_seals_a_generated_key_once_and_mirrors_public_files() {
        let l = layout("sealnew");
        std::fs::write(format!("{}/{SECRET}", l.rdir), KEY).unwrap();
        std::fs::write(format!("{}/{PUBLIC}", l.rdir), b"pub1").unwrap();
        std::fs::write(format!("{}/{HOSTNAME}", l.rdir), b"one.onion\n").unwrap();
        let note = seal_new_at(&l.keys, &l.ram, "myapp", PASS).unwrap();
        assert_eq!(
            note.as_deref(),
            Some("Sealed the new key for myapp at rest (hs_ed25519_secret_key.enc).")
        );
        let sealed = format!("{}/{SEALED}", l.vol);
        assert_eq!(mode_of(&sealed), 0o600);
        let env = std::fs::read(&sealed).unwrap();
        assert_eq!(keycrypt::decrypt(&env, PASS).unwrap().0, KEY);
        for (n, want) in [(PUBLIC, &b"pub1"[..]), (HOSTNAME, &b"one.onion\n"[..])] {
            let f = format!("{}/{n}", l.vol);
            assert_eq!(
                (std::fs::read(&f).unwrap(), mode_of(&f)),
                (want.to_vec(), 0o600)
            );
        }
        assert!(
            !exists(&format!("{}/{SECRET}", l.vol)),
            "the volume never sees the plaintext"
        );
        // idempotent: an existing envelope is never replaced
        std::fs::write(format!("{}/{SECRET}", l.rdir), b"a different key in ram").unwrap();
        assert_eq!(seal_new_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        assert_eq!(std::fs::read(&sealed).unwrap(), env);
        // public files follow changes
        std::fs::write(format!("{}/{HOSTNAME}", l.rdir), b"two.onion\n").unwrap();
        assert_eq!(seal_new_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        assert_eq!(
            std::fs::read(format!("{}/{HOSTNAME}", l.vol)).unwrap(),
            b"two.onion\n"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn seal_new_without_a_key_in_ram_seals_nothing() {
        let l = layout("sealnone");
        std::fs::write(format!("{}/{HOSTNAME}", l.rdir), b"h.onion\n").unwrap();
        assert_eq!(seal_new_at(&l.keys, &l.ram, "myapp", PASS), Ok(None));
        assert!(!exists(&format!("{}/{SEALED}", l.vol)));
        assert_eq!(
            std::fs::read(format!("{}/{HOSTNAME}", l.vol)).unwrap(),
            b"h.onion\n"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn seal_new_with_a_short_passphrase_fails_and_seals_nothing() {
        let l = layout("sealshort");
        std::fs::write(format!("{}/{SECRET}", l.rdir), KEY).unwrap();
        let e = seal_new_at(&l.keys, &l.ram, "myapp", b"short").unwrap_err();
        assert!(e.starts_with("the passphrase is 5 characters;"), "{e}");
        assert!(!exists(&format!("{}/{SEALED}", l.vol)));
    }

    /// (envelope on the volume, hostname in RAM, hostname on the volume, settled?)
    type SettledCase = (bool, Option<&'static [u8]>, Option<&'static [u8]>, bool);

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn settled_needs_an_envelope_and_a_matching_hostname_in_both_places() {
        // (envelope on volume, hostname in ram, hostname on volume)
        let cases: [SettledCase; 9] = [
            (true, Some(b"a.onion\n"), Some(b"a.onion\n"), true),
            (false, Some(b"a.onion\n"), Some(b"a.onion\n"), false),
            (true, None, Some(b"a.onion\n"), false),
            (true, Some(b"a.onion\n"), None, false),
            (true, None, None, false),
            (true, Some(b"a.onion\n"), Some(b"b.onion\n"), false),
            (false, None, None, false),
            (true, Some(b""), Some(b""), true),
            (true, Some(&[b'h'; 257]), Some(&[b'h'; 257]), false), // over the 256-byte cap
        ];
        for (i, (env, ramh, volh, want)) in cases.iter().enumerate() {
            let l = layout(&format!("settled{i}"));
            if *env {
                std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
            }
            if let Some(h) = ramh {
                std::fs::write(format!("{}/{HOSTNAME}", l.rdir), h).unwrap();
            }
            if let Some(h) = volh {
                std::fs::write(format!("{}/{HOSTNAME}", l.vol), h).unwrap();
            }
            assert_eq!(settled_at(&l.keys, &l.ram, "myapp"), *want, "case {i}");
        }
        let l = layout("settled256");
        std::fs::write(format!("{}/{SEALED}", l.vol), envelope()).unwrap();
        for d in [&l.rdir, &l.vol] {
            std::fs::write(format!("{d}/{HOSTNAME}"), [b'h'; 256]).unwrap();
        }
        assert!(
            settled_at(&l.keys, &l.ram, "myapp"),
            "exactly 256 bytes is fine"
        );
    }

    // ---- client authorization mirror ---------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn sync_authorized_clients_mirrors_the_volume_exactly() {
        let l = layout("sync");
        let (from, to) = (
            format!("{}/{AUTH_DIR}", l.vol),
            format!("{}/{AUTH_DIR}", l.rdir),
        );
        std::fs::create_dir(&from).unwrap();
        std::fs::write(format!("{from}/alice.auth"), b"descriptor:x25519:AAAA\n").unwrap();
        std::fs::write(format!("{from}/bob_2.auth"), b"descriptor:x25519:BBBB\n").unwrap();
        // not clients: wrong suffix, invalid names, no suffix
        for junk in [
            "notes.txt",
            "Carol.auth",
            "-dash.auth",
            ".auth",
            "alice.auth.bak",
            "alice",
        ] {
            std::fs::write(format!("{from}/{junk}"), b"x").unwrap();
        }
        sync_authorized_clients(&l.vol, &l.rdir).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&to)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["alice.auth", "bob_2.auth"]);
        assert_eq!(mode_of(&to), 0o700);
        for (n, c) in [("alice.auth", "AAAA"), ("bob_2.auth", "BBBB")] {
            let f = format!("{to}/{n}");
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                format!("descriptor:x25519:{c}\n")
            );
            assert_eq!(mode_of(&f), 0o600);
        }
        // a client removed from the volume loses access in RAM; an unrelated stale file too
        std::fs::remove_file(format!("{from}/bob_2.auth")).unwrap();
        std::fs::write(format!("{to}/stale.auth"), b"x").unwrap();
        std::fs::write(format!("{to}/not-even-a-client"), b"x").unwrap();
        // and a changed key is replaced
        std::fs::write(format!("{from}/alice.auth"), b"descriptor:x25519:CCCC\n").unwrap();
        sync_authorized_clients(&l.vol, &l.rdir).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&to)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["alice.auth"]);
        assert_eq!(
            std::fs::read_to_string(format!("{to}/alice.auth")).unwrap(),
            "descriptor:x25519:CCCC\n"
        );
        // the volume directory itself is gone: the RAM mirror empties, and stays
        std::fs::remove_dir_all(&from).unwrap();
        sync_authorized_clients(&l.vol, &l.rdir).unwrap();
        assert_eq!(std::fs::read_dir(&to).unwrap().count(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn sync_authorized_clients_creates_nothing_when_there_is_nothing_to_mirror() {
        let l = layout("syncnone");
        sync_authorized_clients(&l.vol, &l.rdir).unwrap();
        assert!(!exists(&format!("{}/{AUTH_DIR}", l.rdir)));
        // an empty volume directory counts as nothing too
        std::fs::create_dir(format!("{}/{AUTH_DIR}", l.vol)).unwrap();
        sync_authorized_clients(&l.vol, &l.rdir).unwrap();
        assert!(!exists(&format!("{}/{AUTH_DIR}", l.rdir)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn sync_authorized_clients_reports_what_it_cannot_do() {
        let l = layout("syncerr");
        let from = format!("{}/{AUTH_DIR}", l.vol);
        std::fs::create_dir(&from).unwrap();
        std::fs::write(format!("{from}/a.auth"), b"k").unwrap();
        // RAM service directory missing: the mirror directory cannot be created
        let gone = format!("{}/missing/{AUTH_DIR}", l.ram);
        let e = sync_authorized_clients(&l.vol, &format!("{}/missing", l.ram)).unwrap_err();
        assert_eq!(
            e,
            format!("cannot create {gone}: No such file or directory (os error 2)")
        );
        // a stale entry that cannot be removed with remove_file (a directory)
        let to = format!("{}/{AUTH_DIR}", l.rdir);
        std::fs::create_dir(&to).unwrap();
        std::fs::create_dir(format!("{to}/stale")).unwrap();
        let e = sync_authorized_clients(&l.vol, &l.rdir).unwrap_err();
        assert_eq!(
            e,
            format!("cannot remove {to}/stale: Is a directory (os error 21)")
        );
    }

    // ---- file primitives ---------------------------------------------------

    #[test]
    fn passphrase_file_ignores_unset_and_empty_values() {
        assert_eq!(passphrase_file_from(None), None);
        assert_eq!(passphrase_file_from(Some(String::new())), None);
        assert_eq!(
            passphrase_file_from(Some("/run/p".into())),
            Some("/run/p".into())
        );
        assert_eq!(passphrase_file_from(Some(" ".into())), Some(" ".into()));
        assert_eq!(ENV, "HIDDENFORGE_KEY_PASSPHRASE_FILE");
    }

    #[test]
    fn write_atomic_writes_the_mode_replaces_and_leaves_no_temp_file() {
        let d = Tmp::new("wa");
        write_atomic(&d, "f", b"one", 0o640).unwrap();
        assert_eq!(
            (
                std::fs::read(format!("{d}/f")).unwrap(),
                mode_of(&format!("{d}/f"))
            ),
            (b"one".to_vec(), 0o640)
        );
        write_atomic(&d, "f", b"second, longer", 0o600).unwrap();
        assert_eq!(std::fs::read(format!("{d}/f")).unwrap(), b"second, longer");
        assert_eq!(mode_of(&format!("{d}/f")), 0o600);
        let names: Vec<_> = std::fs::read_dir(&*d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, ["f"]);
        // a link at the target is replaced, never followed
        std::fs::write(format!("{d}/victim"), b"keep").unwrap();
        symlink(format!("{d}/victim"), format!("{d}/lnk")).unwrap();
        write_atomic(&d, "lnk", b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(format!("{d}/victim")).unwrap(), b"keep");
        assert_eq!(std::fs::read(format!("{d}/lnk")).unwrap(), b"new");
        assert!(!std::fs::symlink_metadata(format!("{d}/lnk"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn write_atomic_clears_a_planted_temp_name_without_following_it() {
        let d = Tmp::new("waplant");
        std::fs::write(format!("{d}/victim"), b"keep").unwrap();
        let tmp = format!("{d}/.f.{}.tmp", std::process::id());
        symlink(format!("{d}/victim"), &tmp).unwrap();
        write_atomic(&d, "f", b"data", 0o600).unwrap();
        assert_eq!(std::fs::read(format!("{d}/victim")).unwrap(), b"keep");
        assert_eq!(std::fs::read(format!("{d}/f")).unwrap(), b"data");
        assert!(!exists(&tmp));
    }

    #[test]
    #[cfg_attr(miri, ignore = "error text differs under miri (no strerror)")]
    fn write_atomic_names_the_target_when_it_fails() {
        let d = Tmp::new("wafail");
        let dir = format!("{d}/nodir");
        assert_eq!(
            write_atomic(&dir, "f", b"x", 0o600),
            Err(format!(
                "cannot write {dir}/f: No such file or directory (os error 2)"
            ))
        );
        // renaming a file over a directory fails and the temp file does not stay
        std::fs::create_dir(format!("{d}/f")).unwrap();
        let e = write_atomic(&d, "f", b"x", 0o600).unwrap_err();
        assert!(e.starts_with(&format!("cannot write {d}/f: ")), "{e}");
        let names: Vec<_> = std::fs::read_dir(&*d)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, ["f"]);
    }

    #[test]
    fn wipe_overwrites_through_the_open_file_then_removes_it() {
        let d = Tmp::new("wipe");
        let f = format!("{d}/key");
        std::fs::write(&f, KEY).unwrap();
        let mut held = std::fs::File::open(&f).unwrap(); // survives the unlink
        wipe(&f).unwrap();
        assert!(!exists(&f));
        let mut left = Vec::new();
        std::io::Read::read_to_end(&mut held, &mut left).unwrap();
        assert_eq!(
            left,
            vec![0u8; KEY.len()],
            "zeros of the same length, not the key"
        );
        // an empty file is fine too
        std::fs::write(&f, b"").unwrap();
        wipe(&f).unwrap();
        assert!(!exists(&f));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn wipe_refuses_links_directories_and_missing_files() {
        let d = Tmp::new("wiperef");
        let refuse =
            |p: &str| format!("{p} is not a single regular file; refusing to overwrite it");
        std::fs::write(format!("{d}/a"), KEY).unwrap();
        std::fs::hard_link(format!("{d}/a"), format!("{d}/b")).unwrap();
        for n in ["a", "b"] {
            let p = format!("{d}/{n}");
            assert_eq!(wipe(&p), Err(refuse(&p)));
        }
        assert_eq!(std::fs::read(format!("{d}/a")).unwrap(), KEY, "untouched");
        symlink(format!("{d}/a"), format!("{d}/l")).unwrap();
        assert_eq!(wipe(&format!("{d}/l")), Err(refuse(&format!("{d}/l"))));
        std::fs::create_dir(format!("{d}/dir")).unwrap();
        assert_eq!(wipe(&format!("{d}/dir")), Err(refuse(&format!("{d}/dir"))));
        let m = format!("{d}/none");
        assert_eq!(
            wipe(&m),
            Err(format!("[Errno 2] No such file or directory: '{m}'"))
        );
        if not_root() {
            // not writable: the open fails and the file stays
            std::fs::write(format!("{d}/ro"), KEY).unwrap();
            chmod(&format!("{d}/ro"), 0o400);
            assert_eq!(
                wipe(&format!("{d}/ro")),
                Err("Permission denied (os error 13)".to_string())
            );
            assert_eq!(std::fs::read(format!("{d}/ro")).unwrap(), KEY);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn copy_if_present_copies_with_the_mode_only_when_the_content_changed() {
        let l = layout("copy");
        let (vol, ram) = (&l.vol, &l.rdir);
        std::fs::write(format!("{vol}/{HOSTNAME}"), b"a.onion\n").unwrap();
        copy_if_present(vol, ram, HOSTNAME, 0o640).unwrap();
        let dst = format!("{ram}/{HOSTNAME}");
        assert_eq!(
            (std::fs::read(&dst).unwrap(), mode_of(&dst)),
            (b"a.onion\n".to_vec(), 0o640)
        );
        let ino = std::fs::metadata(&dst).unwrap().ino();
        copy_if_present(vol, ram, HOSTNAME, 0o640).unwrap();
        assert_eq!(
            std::fs::metadata(&dst).unwrap().ino(),
            ino,
            "equal content is not rewritten"
        );
        std::fs::write(format!("{vol}/{HOSTNAME}"), b"b.onion\n").unwrap();
        copy_if_present(vol, ram, HOSTNAME, 0o640).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"b.onion\n", "updated");
        copy_if_present(vol, ram, "absent", 0o600).unwrap();
        assert!(!exists(&format!("{ram}/absent")));
        // a source over 8192 bytes is not copied
        std::fs::write(format!("{vol}/big"), vec![b'x'; 8193]).unwrap();
        copy_if_present(vol, ram, "big", 0o600).unwrap();
        assert!(!exists(&format!("{ram}/big")));
        std::fs::write(format!("{vol}/edge"), vec![b'x'; 8192]).unwrap();
        copy_if_present(vol, ram, "edge", 0o600).unwrap();
        assert_eq!(std::fs::read(format!("{ram}/edge")).unwrap().len(), 8192);
        // a failed copy is an error naming the destination
        let e = copy_if_present(vol, &format!("{ram}/nodir"), HOSTNAME, 0o600).unwrap_err();
        assert!(
            e.starts_with(&format!("cannot write {ram}/nodir/{HOSTNAME}: ")),
            "{e}"
        );
    }

    // ---- the helper process entry point ------------------------------------

    fn run_helper(l: &Layout, op: &str, name: &str, stdin: &[u8]) -> (i32, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = helper_at(
            (&*l.keys, &*l.ram),
            op,
            name,
            std::io::Cursor::new(stdin.to_vec()),
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn helper_rejects_bad_names_before_reading_anything() {
        let l = layout("hname");
        for bad in ["", "Upper", "a_b", "a.b", "../x", "a b", "a/b", "é", "a\n"] {
            assert_eq!(
                run_helper(&l, "unseal", bad, PASS),
                (2, String::new(), String::new()),
                "{bad:?}"
            );
        }
        // digits, lowercase and '-' are the whole alphabet
        for ok in ["a", "z9", "my-app", "0", "-", "a-1-b"] {
            std::fs::create_dir_all(format!("{}/{ok}", l.keys)).unwrap();
            std::fs::create_dir_all(format!("{}/{ok}", l.ram)).unwrap();
            assert_eq!(run_helper(&l, "unseal", ok, PASS).0, 0, "{ok:?}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn helper_caps_the_passphrase_on_stdin_at_4096_bytes() {
        let l = layout("hcap");
        assert_eq!(run_helper(&l, "unseal", "myapp", &vec![b'a'; 4096]).0, 0);
        assert_eq!(
            run_helper(&l, "unseal", "myapp", &vec![b'a'; 4097]),
            (2, String::new(), String::new())
        );
        assert_eq!(run_helper(&l, "unseal", "myapp", &vec![b'a'; 100_000]).0, 2);
        assert_eq!(
            run_helper(&l, "unseal", "myapp", b"").0,
            0,
            "no key involved, so no passphrase needed"
        );
        // an unreadable stdin is the same refusal
        let (mut o, mut e) = (Vec::new(), Vec::new());
        struct Bad;
        impl std::io::Read for Bad {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        assert_eq!(
            helper_at((&*l.keys, &*l.ram), "unseal", "myapp", Bad, &mut o, &mut e),
            2
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn helper_routes_ops_and_maps_results_to_exit_codes() {
        let l = layout("hroute");
        // unknown op: refused
        assert_eq!(
            run_helper(&l, "frobnicate", "myapp", PASS),
            (2, String::new(), String::new())
        );
        assert_eq!(run_helper(&l, "", "myapp", PASS).0, 2);
        assert_eq!(run_helper(&l, "Unseal", "myapp", PASS).0, 2);
        // seal with a key in RAM: the note goes to stdout, exit 0
        std::fs::write(format!("{}/{SECRET}", l.rdir), KEY).unwrap();
        assert_eq!(
            run_helper(&l, "seal", "myapp", PASS),
            (
                0,
                "Sealed the new key for myapp at rest (hs_ed25519_secret_key.enc).\n".to_string(),
                String::new()
            )
        );
        assert!(exists(&format!("{}/{SEALED}", l.vol)));
        // nothing more to do: exit 0, silent
        assert_eq!(
            run_helper(&l, "seal", "myapp", PASS),
            (0, String::new(), String::new())
        );
        // unseal with the right passphrase: exit 0 and the key is in RAM
        let r2 = layout("hroute2");
        std::fs::copy(
            format!("{}/{SEALED}", l.vol),
            format!("{}/{SEALED}", r2.vol),
        )
        .unwrap();
        assert_eq!(
            run_helper(&r2, "unseal", "myapp", PASS),
            (0, String::new(), String::new())
        );
        assert_eq!(std::fs::read(format!("{}/{SECRET}", r2.rdir)).unwrap(), KEY);
        // unseal with the wrong one: exit 1, the message on stderr only
        let r3 = layout("hroute3");
        std::fs::copy(
            format!("{}/{SEALED}", l.vol),
            format!("{}/{SEALED}", r3.vol),
        )
        .unwrap();
        assert_eq!(
            run_helper(&r3, "unseal", "myapp", WRONG),
            (1, String::new(), format!("myapp: {AUTH_FAILED}\n"))
        );
        // migration through the helper prints the note on stdout
        let r4 = layout("hroute4");
        std::fs::write(format!("{}/{SECRET}", r4.vol), KEY).unwrap();
        let (code, out, err) = run_helper(&r4, "unseal", "myapp", PASS);
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(
            out.starts_with("Sealed the key for myapp: it is now encrypted at rest"),
            "{out}"
        );
        assert!(out.ends_with(".\n"));
    }
}
