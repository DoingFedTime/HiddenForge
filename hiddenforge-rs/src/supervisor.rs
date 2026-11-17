//! PID 1: generate the torrc, prepare the key volume, start Tor as the tor user,
//! keep the upload watcher and the guards alive, publish addresses once the
//! service is reachable, and restart (exit non-zero) when a backend moves.
//! Port of entrypoint.main(); same timings, budgets and messages.

use crate::fsops::{self, PublishState};
use crate::health;
use crate::keycrypt::Secret;
use crate::landlock;
use crate::privs::{self, AsUser};
use crate::py::{self, Json};
use crate::sealed;
use crate::torrc;
use std::process::Child;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DATA_DIR: &str = "/var/lib/tor";
const TORRC_PATH: &str = "/etc/tor/torrc";
const DROPPED_MAPPINGS: &str = "/var/lib/tor/dropped-mappings";
const GUARDS_STATE: &str = "/var/lib/tor/vanguards.state";
const GUARDS_MAX_RESTARTS: u32 = 5;
const GUARDS_RETRY: f64 = 10.0;
const GUARDS_COOLDOWN: f64 = 600.0;
const UPLOAD_WATCHER_RETRY: f64 = GUARDS_RETRY;
const GATE_RETRY: f64 = 10.0;
const BACKEND_RECHECK: Duration = Duration::from_secs(30);
const BACKEND_MOVE_CONFIRMATIONS: u32 = 2;

static SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    SIGNAL.store(sig, Ordering::SeqCst);
}

fn install_signals() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe {
            libc::signal(
                sig,
                on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
    }
}

fn say(lines: &mut Vec<String>) {
    for l in lines.drain(..) {
        println!("{l}");
    }
}

struct Ctx {
    tor: Option<AsUser>,
    home: String,
    exe: String,
    landlock: bool,
    /// Full vanguards (opt-in): where the pinned layers persist, and the one
    /// directory the monitor may write (leaked once: Landlock rules are 'static).
    vanguards_state: Option<(&'static str, &'static str)>,
}

/// The variable that turns full vanguards on.
pub const VANGUARDS_ENV: &str = "HIDDENFORGE_VANGUARDS";
const VANGUARDS_STATE_FILE: &str = "vanguards-full.state";

/// `HIDDENFORGE_VANGUARDS`: unset/"lite" (Tor's vanguards-lite, the default) or
/// "full". Anything else is refused rather than guessed.
fn vanguards_mode() -> Result<bool, String> {
    match std::env::var(VANGUARDS_ENV).as_deref() {
        Err(_) | Ok("") | Ok("lite") => Ok(false),
        Ok("full") => Ok(true),
        Ok(v) => Err(format!(
            "{VANGUARDS_ENV}={} is not a mode; use lite (the default) or full",
            py::safe_str(v)
        )),
    }
}

/// A command plus the Landlock ruleset its child enforces before exec. Keep it
/// alive until the child has been spawned.
struct Cmd {
    cmd: std::process::Command,
    _rules: Option<landlock::Ruleset>,
}

impl Ctx {
    /// A helper as the tor user, confined to the reader rules. The returned
    /// Cmd must stay alive until the child is spawned (it holds the ruleset).
    fn self_cmd(&self, argv0: &str, args: &[&str]) -> Cmd {
        self.confined(argv0, args, &landlock::reader_rules())
    }

    /// Our own binary as the tor user, confined to `rules` and with no TCP.
    fn confined(&self, argv0: &str, args: &[&str], rules: &[(&str, u64)]) -> Cmd {
        use std::os::unix::process::CommandExt;
        let mut cmd = privs::command(&self.exe, Some(argv0), args, self.tor, &self.home);
        let rs = match helper_confinement(self.landlock, || landlock::build(rules, true)) {
            Ok(rs) => rs,
            Err(e) => {
                println!("Warning: cannot build the Landlock ruleset for the {argv0} helper ({e}); refusing to start it with weaker confinement.");
                refuse_spawn(&mut cmd);
                None
            }
        };
        if let Some(r) = rs.as_ref() {
            let fd = r.fd();
            // SAFETY: the closure only makes two system calls (no allocation),
            // and the ruleset fd stays open until the spawn returns (held in Cmd).
            unsafe {
                cmd.pre_exec(move || match landlock::enforce_fd(fd) {
                    0 => Ok(()),
                    e => Err(std::io::Error::from_raw_os_error(e)),
                });
            }
        }
        Cmd { cmd, _rules: rs }
    }
}

/// The ruleset a helper runs under. With Landlock enforced on the supervisor, a
/// helper whose own (narrower, no-TCP) ruleset cannot be built is an error, never
/// a silent fallback to the supervisor's wider one.
fn helper_confinement(
    landlock_on: bool,
    build: impl FnOnce() -> Result<landlock::Ruleset, String>,
) -> Result<Option<landlock::Ruleset>, String> {
    if landlock_on {
        build().map(Some)
    } else {
        Ok(None)
    }
}

/// How often Tor's state file is copied to the key volume while it runs (Tor
/// itself rewrites it at most about hourly, and at exit).
const TOR_STATE_SAVE_EVERY: f64 = 600.0;

/// Copy Tor's state file to (`save`) or from (`load`) the key directory of
/// service `name`, as the tor user. `Ok(false)`: nothing to copy yet.
fn tor_state(ctx: &Ctx, root: bool, op: &str, name: &str) -> Result<bool, String> {
    if !root {
        return match crate::torstate::helper(op, name) {
            0 => Ok(true),
            3 => Ok(false),
            _ => Err("the copy failed".into()),
        };
    }
    let c = ctx.confined(
        "hiddenforge",
        &["__tor-state", op, name],
        &landlock::watcher_rules(),
    );
    match privs::run_timeout(c.cmd, Duration::from_secs(30)) {
        Ok((Some(0), _, _)) => Ok(true),
        Ok((Some(3), _, _)) => Ok(false),
        Ok((_, _, err)) => Err(String::from_utf8_lossy(&err).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Make `cmd` fail at spawn (EPERM) without running anything: every caller
/// already handles a spawn error.
fn refuse_spawn(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure makes no system call and does not allocate.
    unsafe {
        cmd.pre_exec(|| Err(std::io::Error::from_raw_os_error(libc::EPERM)));
    }
}

/// Sleep up to `d`, waking at once for a shutdown signal.
fn nap(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end && SIGNAL.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(
            Duration::from_millis(50).min(end.saturating_duration_since(Instant::now())),
        );
    }
}

static SPAWN_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn warn_spawn(what: &str, e: &std::io::Error) {
    if !SPAWN_WARNED.swap(true, Ordering::SeqCst) {
        println!("Warning: could not start {what}: {e} (reported once)");
    }
}

fn socket_ready(ctx: &Ctx) -> bool {
    let c = ctx.self_cmd("hiddenforge", &["__is-socket", health::CONTROL_SOCKET]);
    match privs::run_timeout(c.cmd, Duration::from_secs(10)) {
        Ok((Some(0), _, _)) => true,
        Ok(_) => false,
        Err(e) => {
            warn_spawn("the control-socket probe", &e);
            false
        }
    }
}

fn service_reachable(ctx: &Ctx) -> bool {
    let c = ctx.self_cmd("hiddenforge", &["healthcheck", "--json"]);
    let Ok((_, out, _)) = privs::run_timeout(c.cmd, Duration::from_secs(15)) else {
        return false;
    };
    let text = String::from_utf8_lossy(&out);
    matches!(
        py::parse(text.trim()).and_then(|d| d.get("hidden_service_reachable").cloned()),
        Some(Json::Bool(true))
    )
}

/// (backend name, IP the torrc uses or None if it never resolved, IPs it resolves to now)
type Moved = (String, Option<String>, Vec<String>);

struct BackendWatch {
    moved: Arc<Mutex<Option<Moved>>>,
}

impl BackendWatch {
    fn start(recorded: &[(String, String)], pending: &[String]) -> BackendWatch {
        let moved = Arc::new(Mutex::new(None));
        let mut names: Vec<(String, Option<String>)> = recorded
            .iter()
            .map(|(n, ip)| (n.clone(), Some(ip.clone())))
            .collect();
        for p in pending {
            if !names.iter().any(|(n, _)| n == p) {
                names.push((p.clone(), None));
            }
        }
        if !names.is_empty() {
            let slot = Arc::clone(&moved);
            std::thread::spawn(move || {
                let mut misses = vec![0u32; names.len()];
                loop {
                    std::thread::sleep(BACKEND_RECHECK);
                    for (i, (name, old)) in names.iter().enumerate() {
                        let Ok(addrs) = torrc::libc_resolve(name) else {
                            misses[i] = 0;
                            continue;
                        };
                        let mut current: Vec<String> = addrs
                            .iter()
                            .filter_map(|a| torrc::parse_ipv4_strict(a).map(torrc::fmt_ipv4))
                            .collect();
                        current.sort();
                        current.dedup();
                        if current.is_empty() || old.as_ref().is_some_and(|o| current.contains(o)) {
                            misses[i] = 0;
                            continue;
                        }
                        misses[i] += 1;
                        if misses[i] >= BACKEND_MOVE_CONFIRMATIONS {
                            if let Ok(mut m) = slot.lock() {
                                *m = Some((name.clone(), old.clone(), current));
                            }
                            return;
                        }
                    }
                }
            });
        }
        BackendWatch { moved }
    }
}

fn now_s(start: Instant) -> f64 {
    start.elapsed().as_secs_f64()
}

impl Ctx {
    /// Deliver a signal as the tor user (see privs::signal).
    fn signal_as_tor(&self, pid: u32, sig: i32) -> bool {
        let c = self.self_cmd(
            "hiddenforge",
            &["__kill", &pid.to_string(), &sig.to_string()],
        );
        matches!(
            privs::run_timeout(c.cmd, Duration::from_secs(5)),
            Ok((Some(0), _, _))
        )
    }
}

fn shutdown(
    ctx: &Ctx,
    watcher: &mut Option<Child>,
    guards: &mut Option<Child>,
    tor: &mut Option<Child>,
) {
    let k = |p: u32, s: i32| ctx.signal_as_tor(p, s);
    privs::kill_proc(watcher, "upload watcher", Duration::from_secs(5), &k);
    privs::kill_proc(guards, "Vanguards", Duration::from_secs(5), &k);
    privs::kill_proc(tor, "Tor", Duration::from_secs(10), &k);
}

fn start_guards(ctx: &Ctx) -> std::io::Result<Child> {
    let mut rules = landlock::guards_rules();
    let mut args = vec![
        "--control_socket",
        health::CONTROL_SOCKET,
        "--state",
        GUARDS_STATE,
        "--loglevel",
        "NOTICE",
        "--disable_vanguards",
    ];
    if let Some((state, dir)) = ctx.vanguards_state {
        args = vec![
            "--control_socket",
            health::CONTROL_SOCKET,
            "--state",
            state,
            "--loglevel",
            "NOTICE",
        ];
        // The one directory full vanguards may write: where the state lives.
        rules.push((dir, landlock::RW));
    }
    println!(
        "Starting Vanguards: {} {}",
        health::GUARDS_ARGV0,
        args.join(" ")
    );
    let mut c = ctx.confined(health::GUARDS_ARGV0, &args, &rules);
    c.cmd.spawn()
}

fn start_upload_watcher(ctx: &Ctx) -> std::io::Result<Child> {
    let mut c = ctx.confined(
        "hiddenforge-upload-watch",
        &["healthcheck", "--watch-uploads"],
        &landlock::watcher_rules(),
    );
    c.cmd.spawn()
}

pub fn run() -> i32 {
    install_signals();
    let mut log: Vec<String> = Vec::new();
    let Some((tor_uid, tor_gid, home)) = fsops::getpwnam("tor") else {
        println!("FATAL: there is no tor user in /etc/passwd");
        return 1;
    };
    let root = privs::is_root();
    let mut ctx = Ctx {
        tor: root.then_some(AsUser {
            uid: tor_uid,
            gid: tor_gid,
        }),
        home: if home.is_empty() {
            DATA_DIR.into()
        } else {
            home
        },
        exe: privs::self_exe(),
        landlock: false,
        vanguards_state: None,
    };

    // Sealed keys (opt-in): the passphrase is read once, now, and held only in memory.
    let pass: Option<Secret> = match sealed::passphrase_file() {
        None => None,
        Some(f) => match crate::keycrypt::read_passphrase(&f) {
            Ok(p) => Some(p),
            Err(e) => {
                println!("FATAL: key encryption at rest is enabled ({}) but {e}. Refusing to start: without the key Tor would create a new one, and the .onion address would change.", sealed::ENV);
                return 1;
            }
        },
    };

    if root {
        // _assert_can_drop_privileges: one probe turns an RLIMIT_NPROC failure into a named error.
        let pc = ctx.self_cmd("hiddenforge", &["__true"]);
        let probe = privs::run_timeout(pc.cmd, Duration::from_secs(10));
        let failed = match &probe {
            Ok((Some(0), _, _)) => None,
            Ok((_, _, err)) => Some(String::from_utf8_lossy(err).trim().to_string()),
            Err(e) => Some(py::strerror(e.raw_os_error().unwrap_or(0))),
        };
        if let Some(detail) = failed {
            let detail = if detail.is_empty() {
                "privilege drop failed".to_string()
            } else {
                detail
            };
            println!(
                "FATAL: cannot switch to the tor user: {detail}. If this deployment sets a low `ulimits.nproc`, remove it: \
                 RLIMIT_NPROC is counted per host uid, and uid 100 is shared with other containers (i2pforge's i2pd is \
                 also uid 100). Use `pids_limit` for process containment instead."
            );
            return 1;
        }
    } else {
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if me != tor_uid {
            println!(
                "FATAL: started as uid {me}, but no-root mode runs as the tor user ({tor_uid}:{tor_gid}). Start the \
                 container as root (the default) or with user {tor_uid}:{tor_gid}."
            );
            return 1;
        }
        if let Ok(st) = fsops::lstat(torrc::KEYS_ROOT) {
            if st.st_uid != tor_uid {
                println!(
                    "FATAL: no-root mode: the key folder {} is owned by uid {}, not {tor_uid}. Make it owned by \
                     {tor_uid}:{tor_gid} once on the host (rootless Podman: `podman unshare chown -R {tor_uid}:{tor_gid} \
                     <folder>`; Docker: `sudo chown -R {tor_uid}:{tor_gid} <folder>`), or use the default mode. \
                     `hiddenforge setup --no-root` does this for you.",
                    torrc::KEYS_ROOT,
                    st.st_uid
                );
                return 1;
            }
        }
    }

    // ── Generate torrc ──────────────────────────────────────────────────────
    println!("Generating Tor configuration...");
    let generated = (|| -> fsops::R<torrc::Torrc> {
        if fsops::lstat(torrc::KEYS_ROOT).is_ok() {
            fsops::chmod_dir_nofollow(torrc::KEYS_ROOT, 0o751, false)?;
        }
        let env = torrc::python_environ();
        let mut t = torrc::build(&env, &torrc::libc_resolve);
        log.extend(t.log.iter().cloned());
        say(&mut log);
        for d in &t.hs_dirs {
            fsops::prepare_hs_dir(d, tor_uid, tor_gid, &mut log)?;
            say(&mut log);
        }
        if pass.is_none() {
            // A sealed key with no passphrase configured: Tor would see no key and
            // create a new one, silently changing the address. Never let it.
            for d in &t.hs_dirs {
                if fsops::lstat(&format!("{d}/hs_ed25519_secret_key.enc")).is_ok()
                    && fsops::lstat(&format!("{d}/hs_ed25519_secret_key")).is_err()
                {
                    return Err(fsops::PyErr::runtime(format!(
                        "{d} holds an encrypted key (hs_ed25519_secret_key.enc) but {} is not set. Refusing to start: Tor would create a new key and the .onion address would change. Set it to the passphrase file (see `hiddenforge setup --encrypt-keys`).",
                        sealed::ENV
                    )));
                }
            }
        }
        if pass.is_some() {
            // Tor's HiddenServiceDir moves to the tmpfs; the volume keeps only
            // the sealed key, the public key and the hostname.
            // Create every directory first and hand them to tor leaves-first:
            // without DAC_OVERRIDE (rootless Podman) root cannot create inside a
            // directory that already belongs to tor.
            fsops::mkdir_owned(sealed::RAM, 0, 0)?;
            let mut ram_dirs = Vec::new();
            for d in &t.hs_dirs {
                let name = d.rsplit('/').next().unwrap_or("").to_string();
                let ram = format!("{}/{name}", sealed::RAM);
                fsops::mkdir_owned(&ram, tor_uid, tor_gid)?;
                t.content = t.content.replace(
                    &format!("HiddenServiceDir     {d}\n"),
                    &format!("HiddenServiceDir     {ram}\n"),
                );
                ram_dirs.push(ram);
            }
            fsops::mkdir_owned(sealed::RAM, tor_uid, tor_gid)?;
            t.hs_dirs = ram_dirs;
            println!(
                "Key encryption at rest is on: keys are decrypted into {} at start.",
                sealed::RAM
            );
        }
        fsops::write_nofollow(
            TORRC_PATH,
            t.content.as_bytes(),
            0o640,
            Some((tor_uid, tor_gid)),
        )?;
        println!("Generated Tor configuration at {TORRC_PATH}");
        Ok(t)
    })();
    let conf = match generated {
        Ok(t) => {
            println!("Tor configuration generated successfully.");
            t
        }
        Err(e) => {
            say(&mut log);
            println!("Error generating configuration: {e}");
            return 1;
        }
    };

    // ── Full vanguards (opt-in) ─────────────────────────────────────────────
    match vanguards_mode() {
        Err(e) => {
            println!("FATAL: {e}");
            return 1;
        }
        Ok(false) => {}
        Ok(true) => {
            if conf.content.lines().any(|l| l.starts_with("Sandbox 1")) {
                println!(
                    "FATAL: {VANGUARDS_ENV}=full needs TOR_SANDBOX=0. Tor's sandbox rejects every \
                     SETCONF, and pinning the layer-2 and layer-3 guards is a SETCONF. Set both, or \
                     leave {VANGUARDS_ENV} unset for Tor's vanguards-lite with the sandbox."
                );
                return 1;
            }
            // Persist on the key volume (the DataDirectory is a tmpfs): the
            // first service's directory, which the tor user owns.
            let mut names: Vec<String> = conf
                .hs_dirs
                .iter()
                .filter_map(|d| d.rsplit('/').next().map(String::from))
                .collect();
            names.sort();
            let Some(first) = names.first() else {
                println!("FATAL: {VANGUARDS_ENV}=full needs at least one service");
                return 1;
            };
            let state = format!("{}/{first}/{VANGUARDS_STATE_FILE}", torrc::KEYS_ROOT);
            println!(
                "Full vanguards: layer-2 and layer-3 guards are pinned and persist in {state}. \
                 Tor's sandbox is off for this mode (TOR_SANDBOX=0); the engine's seccomp profile still applies."
            );
            let dir = format!("{}/{first}", torrc::KEYS_ROOT);
            ctx.vanguards_state = Some((
                Box::leak(state.into_boxed_str()),
                Box::leak(dir.into_boxed_str()),
            ));
        }
    }

    // Held for the container's life: once /var/lib/tor is the tor user's 0700,
    // root (without DAC_OVERRIDE, as under rootless Podman) cannot reach the key
    // volume by path any more, but this descriptor still reaches it.
    let keys_fd = match fsops::open_dir_nofollow(torrc::KEYS_ROOT) {
        Ok(fd) => Some(fd),
        Err(e) => {
            println!(
                "Warning: cannot open {}: {e}; addresses will not be published.",
                torrc::KEYS_ROOT
            );
            None
        }
    };

    fsops::write_dropped_mappings(DROPPED_MAPPINGS, &conf.dropped, tor_uid, tor_gid, &mut log);
    say(&mut log);

    // ── Fix DataDirectory ownership ─────────────────────────────────────────
    if fsops::lstat(DATA_DIR).is_ok() {
        if let Err(e) = fsops::chmod_dir_nofollow(DATA_DIR, 0o700, true) {
            println!("Error preparing {DATA_DIR}: {e}");
            return 1;
        }
        if root {
            let c = std::ffi::CString::new(DATA_DIR).unwrap_or_default();
            // SAFETY: valid C string; lchown never follows a link.
            if unsafe { libc::lchown(c.as_ptr(), tor_uid, tor_gid) } != 0 {
                println!(
                    "Error preparing {DATA_DIR}: {}",
                    py::oserror_path(py::last_errno(), DATA_DIR)
                );
                return 1;
            }
        }
    }

    // ── Give up the capabilities setup needed ───────────────────────────────
    if root {
        privs::drop_setup_capabilities(privs::POST_SETUP_CAPS, &mut log);
    } else {
        // No-root mode: there is nothing to keep. Clear whatever the runtime left.
        privs::drop_setup_capabilities(0, &mut log);
        log.retain(|l| !l.starts_with("Note: this runtime did not grant"));
        log.push(format!(
            "No-root mode: running as uid {tor_uid} with no capabilities."
        ));
    }
    say(&mut log);

    // ── Sealed keys: decrypt into RAM before Tor starts ─────────────────────
    let names: Vec<String> = conf
        .hs_dirs
        .iter()
        .map(|d| d.rsplit('/').next().unwrap_or("").to_string())
        .collect();
    if let Some(p) = pass.as_ref() {
        for n in &names {
            let r = if root {
                let c = ctx.confined(
                    "hiddenforge",
                    &["__keys", "unseal", n],
                    &landlock::watcher_rules(),
                );
                match privs::run_with_input(c.cmd, &p.0, Duration::from_secs(120)) {
                    Ok((Some(0), out, _)) => Ok(String::from_utf8_lossy(&out).trim().to_string()),
                    Ok((_, _, err)) => Err(String::from_utf8_lossy(&err).trim().to_string()),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                sealed::unseal(n, &p.0).map(|o| o.unwrap_or_default())
            };
            match r {
                Ok(note) if !note.is_empty() => println!("{note}"),
                Ok(_) => {}
                Err(e) => {
                    println!("FATAL: cannot unseal the key for {n}: {e}. Refusing to start: Tor would create a new key and the .onion address would change.");
                    return 1;
                }
            }
        }
    }

    // ── Landlock: confine the supervisor (and so Tor) to what they use ──────
    match landlock::build(&landlock::supervisor_rules(), false).and_then(|r| r.enforce().map(|()| r.abi)) {
        Ok(abi) => {
            ctx.landlock = true;
            println!("Landlock enforced (ABI {abi}): filesystem access limited to what Tor and the supervisor use; helpers have no TCP.");
        }
        Err(e) => println!("Note: Landlock not applied ({e}); continuing with the capability, seccomp and sandbox layers."),
    }

    // ── Tor's guards: restore the state file Tor saved last time ────────────
    let state_home = names.iter().min().cloned();
    if let Some(n) = state_home.as_deref() {
        match tor_state(&ctx, root, "load", n) {
            Ok(true) => println!(
                "Restored Tor's saved state (its entry guards) from {}/{n}.",
                torrc::KEYS_ROOT
            ),
            Ok(false) => {}
            Err(e) => println!(
                "Warning: could not restore Tor's saved state: {e}. Tor starts with fresh guards."
            ),
        }
    }
    let save_state = |why: &str| {
        if let Some(n) = state_home.as_deref() {
            if let Err(e) = tor_state(&ctx, root, "save", n) {
                println!("Warning: could not save Tor's state ({why}): {e}");
            }
        }
    };
    let mut next_state_save = TOR_STATE_SAVE_EVERY;

    // ── Start Tor ───────────────────────────────────────────────────────────
    println!("Starting Tor...");
    let mut tor = match privs::command("tor", None, &["-f", TORRC_PATH], ctx.tor, &ctx.home).spawn()
    {
        Ok(c) => Some(c),
        Err(e) => {
            println!(
                "FATAL: could not start Tor: {}",
                py::strerror(e.raw_os_error().unwrap_or(0))
            );
            return 1;
        }
    };
    if root {
        if let Some(t) = tor.as_ref() {
            if !privs::assert_process_dropped(t, "Tor", &mut log) {
                say(&mut log);
                privs::kill_proc(&mut tor, "Tor", Duration::from_secs(5), &|p, s| {
                    ctx.signal_as_tor(p, s)
                });
                return 1;
            }
        }
    }

    let start = Instant::now();
    let mut watcher: Option<Child> = None;
    let mut guards: Option<Child> = None;
    let mut g_restarts: u32 = 0;
    let mut g_last_start = 0.0f64;
    let mut g_next = 0.0f64;
    let mut w_next = 0.0f64;

    // ── Wait for the control socket, then start the clients ─────────────────
    println!("Waiting for Tor control socket...");
    let wait_start = Instant::now();
    let waited: Result<(), String> = loop {
        if SIGNAL.load(Ordering::SeqCst) != 0 {
            break Ok(());
        }
        if socket_ready(&ctx) {
            nap(Duration::from_millis(500));
            println!("Control socket ready.");
            break Ok(());
        }
        if let Some(Ok(Some(st))) = tor.as_mut().map(Child::try_wait) {
            break Err(format!(
                "could not start Vanguards: Tor exited (code {}) before its control socket appeared. Will keep retrying.",
                st.code().unwrap_or(-1)
            ));
        }
        if wait_start.elapsed() > Duration::from_secs(120) {
            break Err(
                "Tor control socket not found after 120s. Will keep retrying Vanguards.".into(),
            );
        }
        nap(Duration::from_millis(500));
    };
    match waited {
        Ok(()) if SIGNAL.load(Ordering::SeqCst) == 0 => {
            watcher = start_upload_watcher(&ctx).ok();
            match start_guards(&ctx) {
                Ok(c) => {
                    guards = Some(c);
                    g_last_start = now_s(start);
                    println!("Vanguards addon started.");
                }
                Err(e) => println!("Warning: could not start Vanguards: {e}. Will keep retrying."),
            }
        }
        Ok(()) => {}
        Err(msg) => println!("Warning: {msg}"),
    }

    let backend = BackendWatch::start(&conf.resolved, &conf.unresolved);
    let mut publish = PublishState::default();
    let mut gate_no_until: Option<f64> = None;
    let mut next_seal = 0.0f64;
    let mut seal_warned = false;

    loop {
        nap(Duration::from_secs(1));
        let sig = SIGNAL.load(Ordering::SeqCst);
        if sig != 0 {
            println!("Received signal {sig}, shutting down...");
            shutdown(&ctx, &mut watcher, &mut guards, &mut tor);
            save_state("at shutdown");
            return 0;
        }

        let mut gate = || {
            let now = now_s(start);
            if gate_no_until.is_some_and(|t| now < t) {
                return false;
            }
            if service_reachable(&ctx) {
                gate_no_until = None;
                true
            } else {
                gate_no_until = Some(now + GATE_RETRY);
                false
            }
        };
        let read_as_tor = |path: &str| -> Option<Vec<u8>> {
            ctx.tor?; // only meaningful when we are root and tor is someone else
            let c = ctx.self_cmd("hiddenforge", &["__read-hostname", path]);
            match privs::run_timeout(c.cmd, Duration::from_secs(10)) {
                Ok((Some(0), out, _)) => Some(out),
                _ => None,
            }
        };
        if let Some(kfd) = keys_fd.as_ref() {
            fsops::publish_addresses(
                &conf.hs_dirs,
                torrc::KEYS_ROOT,
                kfd,
                &mut gate,
                &read_as_tor,
                &mut publish,
                &mut log,
            );
        }
        say(&mut log);

        if let Some(Ok(Some(st))) = tor.as_mut().map(Child::try_wait) {
            let rc = st.code().unwrap_or(1);
            println!("Tor exited with code {rc}, shutting down.");
            privs::kill_proc(
                &mut watcher,
                "upload watcher",
                Duration::from_secs(5),
                &|p, s| ctx.signal_as_tor(p, s),
            );
            privs::kill_proc(&mut guards, "Vanguards", Duration::from_secs(5), &|p, s| {
                ctx.signal_as_tor(p, s)
            });
            save_state("after Tor exited");
            return if rc != 0 { rc } else { 1 };
        }

        if let Some(p) = pass.as_ref() {
            if now_s(start) >= next_seal {
                next_seal = now_s(start) + 5.0;
                for n in &names {
                    if sealed::settled(n) && root {
                        continue;
                    }
                    let r = if root {
                        let c = ctx.confined(
                            "hiddenforge",
                            &["__keys", "seal", n],
                            &landlock::watcher_rules(),
                        );
                        match privs::run_with_input(c.cmd, &p.0, Duration::from_secs(120)) {
                            Ok((Some(0), out, _)) => {
                                Ok(String::from_utf8_lossy(&out).trim().to_string())
                            }
                            Ok((_, _, err)) => {
                                Err(String::from_utf8_lossy(&err).trim().to_string())
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    } else if sealed::settled(n) {
                        Ok(String::new())
                    } else {
                        sealed::seal_new(n, &p.0).map(|o| o.unwrap_or_default())
                    };
                    match r {
                        Ok(note) if !note.is_empty() => println!("{note}"),
                        Ok(_) => {}
                        Err(e) => {
                            if !seal_warned {
                                seal_warned = true;
                                println!("Warning: could not seal the key for {n} yet: {e} (retrying; reported once)");
                            }
                        }
                    }
                }
            }
        }

        let moved = backend.moved.lock().ok().and_then(|m| m.clone());
        if let Some((name, old, current)) = moved {
            match old {
                None => println!(
                    "Backend '{}' did not resolve at startup and now resolves to {}. Restarting so the service it was \
                     dropped from is configured (addresses do not change).",
                    py::safe_str(&name),
                    current.join(", ")
                ),
                Some(o) => println!(
                    "Backend '{}' now resolves to {}, but Tor is still forwarding to {o}. Restarting so the onion follows \
                     it (the address itself does not change).",
                    py::safe_str(&name),
                    current.join(", ")
                ),
            }
            shutdown(&ctx, &mut watcher, &mut guards, &mut tor);
            save_state("before restarting");
            return 1;
        }

        let now = now_s(start);
        if now >= next_state_save {
            next_state_save = now + TOR_STATE_SAVE_EVERY;
            save_state("periodic");
        }
        let mut probe: Option<bool> = None;
        let ready = |probe: &mut Option<bool>| *probe.get_or_insert_with(|| socket_ready(&ctx));

        let watcher_dead = match watcher.as_mut() {
            None => true,
            Some(c) => matches!(c.try_wait(), Ok(Some(_))),
        };
        if watcher_dead && now >= w_next {
            w_next = now + UPLOAD_WATCHER_RETRY;
            if ready(&mut probe) {
                if watcher.is_some() {
                    println!("Upload watcher exited; restarting it.");
                }
                watcher = match start_upload_watcher(&ctx) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        println!("Could not start the upload watcher: {e}");
                        None
                    }
                };
            }
        }

        if let Some(Ok(Some(st))) = guards.as_mut().map(Child::try_wait) {
            let code = st
                .code()
                .map_or_else(|| "None".to_string(), |c| c.to_string());
            guards = None;
            if now - g_last_start > 60.0 {
                g_restarts = 0;
            }
            g_restarts += 1;
            if g_restarts > GUARDS_MAX_RESTARTS {
                println!(
                    "Vanguards exited (code {code}) too many times in quick succession; pausing it for {GUARDS_COOLDOWN:.0}s, then trying again."
                );
                g_restarts = 0;
                g_next = now + GUARDS_COOLDOWN;
            } else {
                println!(
                    "Vanguards exited (code {code}), retrying in {GUARDS_RETRY:.0}s (attempt {g_restarts}/{GUARDS_MAX_RESTARTS})..."
                );
                g_next = now + GUARDS_RETRY;
            }
        }

        if guards.is_none() && now >= g_next {
            if !ready(&mut probe) {
                g_next = now + GUARDS_RETRY;
            } else {
                match start_guards(&ctx) {
                    Ok(c) => {
                        guards = Some(c);
                        g_last_start = now;
                        g_next = 0.0;
                        println!("Vanguards addon started.");
                    }
                    Err(e) => {
                        g_restarts += 1;
                        println!("Could not start Vanguards: {e}");
                        if g_restarts > GUARDS_MAX_RESTARTS {
                            println!("Vanguards could not be started; pausing it for {GUARDS_COOLDOWN:.0}s, then trying again.");
                            g_restarts = 0;
                            g_next = now + GUARDS_COOLDOWN;
                        } else {
                            g_next = now + GUARDS_RETRY;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_ruleset_that_cannot_be_built_is_an_error_not_a_fallback() {
        let e = helper_confinement(true, || {
            Err("landlock_add_rule /x: Too many open files".into())
        });
        assert_eq!(
            e.err().as_deref(),
            Some("landlock_add_rule /x: Too many open files")
        );
        let mut called = false;
        let off = helper_confinement(false, || {
            called = true;
            Err("unused".into())
        });
        assert!(
            matches!(off, Ok(None)) && !called,
            "no Landlock: no ruleset, nothing built"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn a_refused_command_never_runs() {
        let dir = std::env::temp_dir().join(format!("hf-refuse-{}", std::process::id()));
        let marker = dir.join("ran");
        std::fs::create_dir_all(&dir).unwrap();
        let mut c = std::process::Command::new("sh");
        c.args(["-c", &format!("touch {}", marker.display())]);
        refuse_spawn(&mut c);
        let err = c.spawn().map(|_| ()).unwrap_err();
        let ran = marker.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        assert!(!ran, "the refused command ran");
    }
}
