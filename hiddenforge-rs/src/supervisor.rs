//! PID 1: generate the torrc, prepare the key volume, start Tor as the tor user,
//! keep the upload watcher and the guards alive, publish addresses once the
//! service is reachable, and restart (exit non-zero) when a backend moves.
//! Port of entrypoint.main(); same timings, budgets and messages.

use crate::fsops::{self, PublishState};
use crate::health;
use crate::privs::{self, AsUser};
use crate::py::{self, Json};
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
        unsafe { libc::signal(sig, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t) };
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
}

impl Ctx {
    fn self_cmd(&self, argv0: &str, args: &[&str]) -> std::process::Command {
        privs::command(&self.exe, Some(argv0), args, self.tor, &self.home)
    }
}

/// Sleep up to `d`, waking at once for a shutdown signal.
fn nap(d: Duration) {
    let end = Instant::now() + d;
    while Instant::now() < end && SIGNAL.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(50).min(end.saturating_duration_since(Instant::now())));
    }
}

fn socket_ready(ctx: &Ctx) -> bool {
    let c = ctx.self_cmd("hiddenforge", &["__is-socket", health::CONTROL_SOCKET]);
    matches!(privs::run_timeout(c, Duration::from_secs(10)), Ok((Some(0), _, _)))
}

fn service_reachable(ctx: &Ctx) -> bool {
    let c = ctx.self_cmd("hiddenforge", &["healthcheck", "--json"]);
    let Ok((_, out, _)) = privs::run_timeout(c, Duration::from_secs(15)) else { return false };
    let text = String::from_utf8_lossy(&out);
    matches!(py::parse(text.trim()).and_then(|d| d.get("hidden_service_reachable").cloned()), Some(Json::Bool(true)))
}

struct BackendWatch {
    moved: Arc<Mutex<Option<(String, Option<String>, Vec<String>)>>>,
}

impl BackendWatch {
    fn start(recorded: &[(String, String)], pending: &[String]) -> BackendWatch {
        let moved = Arc::new(Mutex::new(None));
        let mut names: Vec<(String, Option<String>)> =
            recorded.iter().map(|(n, ip)| (n.clone(), Some(ip.clone()))).collect();
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
        let c = self.self_cmd("hiddenforge", &["__kill", &pid.to_string(), &sig.to_string()]);
        matches!(privs::run_timeout(c, Duration::from_secs(5)), Ok((Some(0), _, _)))
    }
}

fn shutdown(ctx: &Ctx, watcher: &mut Option<Child>, guards: &mut Option<Child>, tor: &mut Option<Child>) {
    let k = |p: u32, s: i32| ctx.signal_as_tor(p, s);
    privs::kill_proc(watcher, "upload watcher", Duration::from_secs(5), &k);
    privs::kill_proc(guards, "Vanguards", Duration::from_secs(5), &k);
    privs::kill_proc(tor, "Tor", Duration::from_secs(10), &k);
}

fn start_guards(ctx: &Ctx) -> std::io::Result<Child> {
    let args = ["--control_socket", health::CONTROL_SOCKET, "--state", GUARDS_STATE, "--loglevel", "NOTICE", "--disable_vanguards"];
    println!("Starting Vanguards: {} {}", health::GUARDS_ARGV0, args.join(" "));
    ctx.self_cmd(health::GUARDS_ARGV0, &args).spawn()
}

fn start_upload_watcher(ctx: &Ctx) -> std::io::Result<Child> {
    ctx.self_cmd("hiddenforge-upload-watch", &["healthcheck", "--watch-uploads"]).spawn()
}

pub fn run() -> i32 {
    install_signals();
    let mut log: Vec<String> = Vec::new();
    let Some((tor_uid, tor_gid, home)) = fsops::getpwnam("tor") else {
        println!("FATAL: there is no tor user in /etc/passwd");
        return 1;
    };
    let root = privs::is_root();
    let ctx = Ctx {
        tor: root.then_some(AsUser { uid: tor_uid, gid: tor_gid }),
        home: if home.is_empty() { DATA_DIR.into() } else { home },
        exe: privs::self_exe(),
    };

    if root {
        // _assert_can_drop_privileges: one probe turns an RLIMIT_NPROC failure into a named error.
        let probe = privs::run_timeout(ctx.self_cmd("hiddenforge", &["__true"]), Duration::from_secs(10));
        let failed = match &probe {
            Ok((Some(0), _, _)) => None,
            Ok((_, _, err)) => Some(String::from_utf8_lossy(err).trim().to_string()),
            Err(e) => Some(py::strerror(e.raw_os_error().unwrap_or(0))),
        };
        if let Some(detail) = failed {
            let detail = if detail.is_empty() { "privilege drop failed".to_string() } else { detail };
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
        let t = torrc::build(&env, &torrc::libc_resolve);
        log.extend(t.log.iter().cloned());
        say(&mut log);
        for d in &t.hs_dirs {
            fsops::prepare_hs_dir(d, tor_uid, tor_gid, &mut log)?;
            say(&mut log);
        }
        fsops::write_nofollow(TORRC_PATH, t.content.as_bytes(), 0o640, Some((tor_uid, tor_gid)))?;
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
                println!("Error preparing {DATA_DIR}: {}", py::oserror_path(py::last_errno(), DATA_DIR));
                return 1;
            }
        }
    }

    // ── Give up the capabilities setup needed ───────────────────────────────
    privs::drop_setup_capabilities(privs::POST_SETUP_CAPS, &mut log);
    say(&mut log);

    // ── Start Tor ───────────────────────────────────────────────────────────
    println!("Starting Tor...");
    let mut tor = match privs::command("tor", None, &["-f", TORRC_PATH], ctx.tor, &ctx.home).spawn() {
        Ok(c) => Some(c),
        Err(e) => {
            println!("FATAL: could not start Tor: {}", py::strerror(e.raw_os_error().unwrap_or(0)));
            return 1;
        }
    };
    if root {
        if let Some(t) = tor.as_ref() {
            if !privs::assert_process_dropped(t, "Tor", &mut log) {
                say(&mut log);
                privs::kill_proc(&mut tor, "Tor", Duration::from_secs(5), &|p, s| ctx.signal_as_tor(p, s));
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
            break Err("Tor control socket not found after 120s. Will keep retrying Vanguards.".into());
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

    loop {
        nap(Duration::from_secs(1));
        let sig = SIGNAL.load(Ordering::SeqCst);
        if sig != 0 {
            println!("Received signal {sig}, shutting down...");
            shutdown(&ctx, &mut watcher, &mut guards, &mut tor);
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
        fsops::publish_addresses(&conf.hs_dirs, torrc::KEYS_ROOT, &mut gate, &mut publish, &mut log);
        say(&mut log);

        if let Some(Ok(Some(st))) = tor.as_mut().map(Child::try_wait) {
            let rc = st.code().unwrap_or(1);
            println!("Tor exited with code {rc}, shutting down.");
            privs::kill_proc(&mut watcher, "upload watcher", Duration::from_secs(5), &|p, s| ctx.signal_as_tor(p, s));
            privs::kill_proc(&mut guards, "Vanguards", Duration::from_secs(5), &|p, s| ctx.signal_as_tor(p, s));
            return if rc != 0 { rc } else { 1 };
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
            return 1;
        }

        let now = now_s(start);
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
            let code = st.code().map_or_else(|| "None".to_string(), |c| c.to_string());
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
