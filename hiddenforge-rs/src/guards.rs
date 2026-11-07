//! bandguards + rendguard: a port of the Vanguards 0.3.1 addon as HiddenForge
//! runs it (`--disable_vanguards`: layer-2/3 pinning is Tor's vanguards-lite,
//! because SETCONF cannot work under Sandbox 1; cbtverify is off by default).
//!
//! The thresholds, the counting, and every decision to close a circuit are the
//! addon's. What is not ported, deliberately:
//!  * layer-2/3 guard selection and the SETCONF calls (disabled in 2.x too),
//!    so the SIGHUP re-apply that would SETCONF is not ported either;
//!  * ExcludeNodes parsing, which only fed guard selection;
//!  * the pickle state file: it lived in the tmpfs DataDirectory and only held
//!    rendguard counts, so it was reset at every container start anyway.
//!    3.0 keeps the counts in memory for the life of the process.
//!
//! One deliberate difference: where the addon divided by a zero weight total
//! (a consensus with no Exit-flagged bandwidth) and crashed, this uses weight 0
//! for those relays and keeps running.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use crate::py;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── bandguards options (Vanguards 0.3.1 defaults) ───────────────────────────
const CIRC_MAX_MEGABYTES: f64 = 0.0;
const CIRC_MAX_AGE_HOURS: f64 = 24.0;
const CIRC_MAX_HSDESC_KILOBYTES: f64 = 30.0;
const CIRC_MAX_DISCONNECTED_SECS: i64 = 30;
pub const CONN_MAX_DISCONNECTED_SECS: i64 = 15;
const CELL_PAYLOAD_SIZE: f64 = 509.0;
const RELAY_HEADER_SIZE: f64 = 11.0;
const RELAY_PAYLOAD_SIZE: f64 = CELL_PAYLOAD_SIZE - RELAY_HEADER_SIZE;
const CELL_DATA_RATE: f64 = RELAY_PAYLOAD_SIZE / CELL_PAYLOAD_SIZE;
const SECS_PER_HOUR: f64 = 3600.0;
const BYTES_PER_KB: f64 = 1024.0;
const BYTES_PER_MB: f64 = 1024.0 * BYTES_PER_KB;
const MAX_CIRC_DESTROY_LAG_SECS: f64 = 2.0;

// ── rendguard options ───────────────────────────────────────────────────────
const REND_USE_GLOBAL_START_COUNT: f64 = 1000.0;
const REND_USE_SCALE_AT_COUNT: f64 = 20000.0;
const REND_USE_RELAY_START_COUNT: f64 = 100.0;
const REND_USE_MAX_USE_TO_BW_RATIO: f64 = 5.0;
const REND_USE_MAX_CONSENSUS_WEIGHT_CHURN: f64 = 1.0;
const REND_USE_CLOSE_CIRCUITS_ON_OVERUSE: bool = true;
const NOT_IN_CONSENSUS_ID: &str = "NOT_IN_CONSENSUS";

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Level {
    Debug = 10,
    Info = 20,
    Notice = 25,
    Warn = 30,
    Error = 40,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Notice => "NOTICE",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "DEBUG" => Level::Debug,
            "INFO" => Level::Info,
            "NOTICE" => Level::Notice,
            "WARN" => Level::Warn,
            "ERROR" => Level::Error,
            _ => return None,
        })
    }
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn asctime() -> String {
    // SAFETY: time/localtime_r/strftime with local buffers.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let mut buf = [0u8; 64];
        let fmt = c"%a %b %d %H:%M:%S %Y";
        let n = libc::strftime(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), &tm);
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }
}

/// What the guards decided to do, and what they want logged.
pub trait Sink {
    fn log(&mut self, level: Level, msg: &str);
    fn close_circuit(&mut self, id: &str);
}

/// A parsed control-port event line ("650 ...").
#[derive(Debug, Default, Clone)]
pub struct Event {
    pub kind: String,
    pub id: String,
    pub status: String,
    pub path: Vec<String>,
    pub kw: BTreeMap<String, String>,
    pub raw: String,
    pub arrived_at: f64,
}

impl Event {
    fn kw(&self, k: &str) -> Option<&str> {
        self.kw.get(k).map(String::as_str)
    }
    fn purpose(&self) -> &str {
        self.kw("PURPOSE").unwrap_or("")
    }
    fn hs_state(&self) -> Option<&str> {
        self.kw("HS_STATE")
    }
}

/// "$FP~nick" / "$FP=nick" / "$FP" -> "FP".
fn fingerprint(entry: &str) -> String {
    let e = entry.strip_prefix('$').unwrap_or(entry);
    e.split(['~', '=']).next().unwrap_or("").to_string()
}

fn is_fp(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse one "650 <KIND> ..." line the way stem does for the events used here.
pub fn parse_event(line: &str, arrived_at: f64) -> Option<Event> {
    let rest = line.strip_prefix("650 ")?;
    let mut toks = rest.split(' ').filter(|t| !t.is_empty());
    let kind = toks.next()?.to_string();
    let toks: Vec<&str> = toks.collect();
    let mut ev = Event { kind: kind.clone(), raw: line.to_string(), arrived_at, ..Event::default() };
    let positional: Vec<&str> = toks.iter().copied().take_while(|t| !t.contains('=')).collect();
    for t in &toks[positional.len()..] {
        if let Some((k, v)) = t.split_once('=') {
            ev.kw.insert(k.to_string(), v.to_string());
        }
    }
    match kind.as_str() {
        "CIRC" | "CIRC_MINOR" => {
            ev.id = positional.first()?.to_string();
            ev.status = positional.get(1)?.to_string();
            if let Some(p) = positional.get(2) {
                ev.path = p.split(',').map(fingerprint).collect();
            }
        }
        "CIRC_BW" => {
            ev.id = ev.kw("ID")?.to_string();
        }
        "ORCONN" => {
            let target = positional.first()?;
            let fp = fingerprint(target);
            ev.path = vec![if target.starts_with('$') && is_fp(&fp) { fp } else { String::new() }];
            ev.status = positional.get(1)?.to_string();
            ev.id = ev.kw("ID").unwrap_or("").to_string();
        }
        "NETWORK_LIVENESS" => ev.status = positional.first()?.to_string(),
        "BW" => {}
        _ => {}
    }
    Some(ev)
}

// ───────────────────────────── bandguards ───────────────────────────────────

#[derive(Debug, Clone, Default)]
struct CircStat {
    circ_id: String,
    is_hsdir: bool,
    dropped_cells_allowed: f64,
    purpose: Option<String>,
    hs_state: Option<String>,
    old_purpose: Option<String>,
    old_hs_state: Option<String>,
    in_use: bool,
    built: bool,
    created_at: f64,
    read_bytes: f64,
    sent_bytes: f64,
    delivered_read_bytes: f64,
    overhead_read_bytes: f64,
    guard_fp: Option<String>,
    possibly_destroyed_at: Option<f64>,
}

impl CircStat {
    fn total_bytes(&self) -> f64 {
        self.read_bytes + self.sent_bytes
    }
    fn dropped_read_cells(&self) -> f64 {
        self.read_bytes / CELL_PAYLOAD_SIZE - (self.delivered_read_bytes + self.overhead_read_bytes) / RELAY_PAYLOAD_SIZE
    }
    fn states(&self) -> String {
        let s = |o: &Option<String>| o.clone().unwrap_or_else(|| "None".into());
        format!(
            "(in state {} {}; old state {} {})",
            s(&self.purpose),
            s(&self.hs_state),
            s(&self.old_purpose),
            s(&self.old_hs_state)
        )
    }
}

#[derive(Debug, Clone, Default)]
struct GuardStat {
    killed_conns: u64,
    killed_conn_at: f64,
    conns_made: u64,
    close_reasons: BTreeMap<String, u64>,
}

#[derive(Default)]
pub struct Bandguards {
    circs: BTreeMap<String, CircStat>,
    circ_order: Vec<String>,
    live_guard_conns: BTreeMap<String, String>, // conn id -> guard fp
    guards: BTreeMap<String, GuardStat>,
    circs_destroyed_total: u64,
    no_conns_since: f64,
    no_circs_since: Option<f64>,
    network_down_since: Option<f64>,
    max_fake_id: i64,
    disconnected_circs: bool,
    disconnected_conns: bool,
}

fn py_int(x: f64) -> i64 {
    x.trunc() as i64
}

impl Bandguards {
    /// `orconn_status` is GETINFO orconn-status; `liveness` is GETINFO network-liveness.
    pub fn new(orconn_status: &str, liveness: &str, t: f64, sink: &mut dyn Sink) -> Bandguards {
        let mut b = Bandguards { no_conns_since: t.trunc(), max_fake_id: -1, ..Bandguards::default() };
        let mut fake_id = 0i64;
        for l in orconn_status.split('\n').filter(|l| !l.is_empty()) {
            if let Some(ev) = parse_event(&format!("650 ORCONN {l} ID={fake_id}"), t) {
                b.orconn_event(&ev, sink);
            }
            fake_id += 1;
        }
        b.max_fake_id = fake_id - 1;
        if liveness != "up" {
            b.network_down_since = Some(t.trunc());
        }
        b
    }

    fn circ_ids(&self) -> impl Iterator<Item = &CircStat> {
        self.circ_order.iter().filter_map(|id| self.circs.get(id))
    }

    pub fn orconn_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        let guard_fp = ev.path.first().cloned().unwrap_or_default();
        self.guards.entry(guard_fp.clone()).or_default();
        let mut id = ev.id.clone();
        match ev.status.as_str() {
            "CONNECTED" => {
                if self.disconnected_conns {
                    let secs = ev.arrived_at - self.no_conns_since;
                    sink.log(Level::Notice, &format!("Reconnected to the Tor network after {} seconds.", py_int(secs)));
                }
                self.live_guard_conns.insert(id, guard_fp.clone());
                if let Some(g) = self.guards.get_mut(&guard_fp) {
                    g.conns_made += 1;
                }
                self.no_conns_since = 0.0;
                self.disconnected_conns = false;
            }
            "CLOSED" | "FAILED" => {
                if !self.live_guard_conns.contains_key(&id) {
                    // _fixup_orconn_event: map onto a fake id from orconn-status.
                    let mut f = self.max_fake_id;
                    while f >= 0 {
                        if self.live_guard_conns.get(&f.to_string()) == Some(&guard_fp) {
                            id = f.to_string();
                        }
                        f -= 1;
                    }
                }
                if self.live_guard_conns.contains_key(&id) {
                    let mut marked = false;
                    let ids: Vec<String> = self.circ_order.clone();
                    for cid in ids {
                        if let Some(c) = self.circs.get_mut(&cid) {
                            if c.in_use && c.guard_fp.as_deref() == Some(guard_fp.as_str()) {
                                c.possibly_destroyed_at = Some(ev.arrived_at);
                                marked = true;
                                sink.log(
                                    Level::Info,
                                    &format!("Marking possibly destroyed circ {} at {}", c.circ_id, py_int(ev.arrived_at)),
                                );
                            }
                        }
                    }
                    if marked {
                        if let Some(g) = self.guards.get_mut(&guard_fp) {
                            g.killed_conn_at = ev.arrived_at;
                        }
                    }
                    self.live_guard_conns.remove(&id);
                    if self.live_guard_conns.is_empty() && self.no_conns_since == 0.0 {
                        self.no_conns_since = ev.arrived_at;
                    }
                }
                if ev.status == "CLOSED" {
                    let reason = ev.kw("REASON").unwrap_or("None").to_string();
                    if let Some(g) = self.guards.get_mut(&guard_fp) {
                        *g.close_reasons.entry(reason).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }
        sink.log(Level::Info, &ev.raw);
    }

    fn circuit_destroyed(&mut self, ev: &Event, sink: &mut dyn Sink) {
        self.circs_destroyed_total += 1;
        let guardfp = ev.path.first().cloned().unwrap_or_default();
        let g = self.guards.entry(guardfp.clone()).or_default();
        if ev.arrived_at - g.killed_conn_at <= MAX_CIRC_DESTROY_LAG_SECS {
            g.killed_conn_at = 0.0;
            g.killed_conns += 1;
            sink.log(Level::Notice, &format!("The connection to guard {guardfp} was closed with a live circuit."));
        }
        sink.log(Level::Info, &format!("The connection to guard {guardfp} was closed with circuit {} on it.", ev.id));
    }

    fn any_circuits_pending(&self, except: Option<&str>) -> bool {
        self.circ_ids().any(|c| !c.built && Some(c.circ_id.as_str()) != except)
    }

    fn set_drop_allowance_for_purpose(c: &mut CircStat, purpose: &str, hs_state: Option<&str>) {
        match purpose {
            "HS_SERVICE_REND" => c.dropped_cells_allowed = f64::from(u8::from(hs_state == Some("HSSR_CONNECTING"))),
            "HS_CLIENT_REND" => c.dropped_cells_allowed = 1.0,
            "HS_CLIENT_INTRO" => c.dropped_cells_allowed = f64::from(u8::from(hs_state == Some("HSCI_DONE"))),
            _ => {}
        }
    }

    pub fn circ_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        if ev.status == "FAILED" && self.no_circs_since.is_none() && self.any_circuits_pending(Some(&ev.id)) {
            self.no_circs_since = Some(ev.arrived_at);
        }
        if ev.status == "FAILED" || ev.status == "CLOSED" {
            if let Some(c) = self.circs.get(&ev.id).cloned() {
                if c.in_use {
                    if let Some(pd) = c.possibly_destroyed_at {
                        if ev.arrived_at - pd <= MAX_CIRC_DESTROY_LAG_SECS && ev.kw("REMOTE_REASON") == Some("CHANNEL_CLOSED") {
                            self.circuit_destroyed(ev, sink);
                        } else {
                            sink.log(
                                Level::Info,
                                &format!(
                                    "Circuit {} possibly destroyed, but outside of the time window ({} - {})",
                                    ev.id,
                                    py_int(ev.arrived_at),
                                    py_int(pd)
                                ),
                            );
                        }
                    }
                }
                sink.log(Level::Debug, &format!("Closed hs circ for {}", ev.raw));
                self.circs.remove(&ev.id);
                self.circ_order.retain(|x| *x != ev.id);
            }
            return;
        }
        let purpose = ev.purpose().to_string();
        let hs_state = ev.hs_state().map(String::from);
        if !self.circs.contains_key(&ev.id) {
            let c = CircStat {
                circ_id: ev.id.clone(),
                is_hsdir: purpose == "HS_CLIENT_HSDIR" || purpose == "HS_SERVICE_HSDIR",
                created_at: now(),
                ..CircStat::default()
            };
            self.circs.insert(ev.id.clone(), c);
            self.circ_order.push(ev.id.clone());
            sink.log(Level::Debug, &format!("Added circ for {}", ev.raw));
        }
        let mut resumed = false;
        if let Some(c) = self.circs.get_mut(&ev.id) {
            c.purpose = Some(purpose.clone());
            c.hs_state.clone_from(&hs_state);
            Self::set_drop_allowance_for_purpose(c, &purpose, hs_state.as_deref());
            if ev.status == "BUILT" || ev.status == "GUARD_WAIT" {
                c.built = true;
                resumed = true;
                if purpose.starts_with("HS_CLIENT") || purpose.starts_with("HS_SERVICE") {
                    c.in_use = true;
                    c.guard_fp = ev.path.first().cloned();
                    sink.log(
                        Level::Debug,
                        &format!("Circ {} now in-use. {} delivered bytes.", ev.id, py_int(c.delivered_read_bytes)),
                    );
                }
            } else if ev.status == "EXTENDED" {
                resumed = true;
            }
        }
        if resumed {
            self.circuits_resumed(ev.arrived_at, sink);
        }
    }

    fn circuits_resumed(&mut self, at: f64, sink: &mut dyn Sink) {
        if self.disconnected_circs {
            let secs = at - self.no_circs_since.unwrap_or(at);
            sink.log(Level::Notice, &format!("Circuit use resumed after {} seconds.", py_int(secs)));
        }
        self.no_circs_since = None;
        self.disconnected_circs = false;
    }

    pub fn circ_minor_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        let Some(c) = self.circs.get_mut(&ev.id) else { return };
        let purpose = ev.purpose().to_string();
        let hs_state = ev.hs_state().map(String::from);
        let old_purpose = ev.kw("OLD_PURPOSE").map(String::from);
        let old_hs_state = ev.kw("OLD_HS_STATE").map(String::from);
        c.purpose = Some(purpose.clone());
        c.hs_state.clone_from(&hs_state);
        c.old_purpose.clone_from(&old_purpose);
        c.old_hs_state.clone_from(&old_hs_state);
        if purpose == "HS_CLIENT_HSDIR" || purpose == "HS_SERVICE_HSDIR" {
            c.is_hsdir = true;
        }
        if ev.status == "PURPOSE_CHANGED" {
            if old_purpose.as_deref() == Some("HS_VANGUARDS") {
                c.in_use = true;
                c.guard_fp = ev.path.first().cloned();
                sink.log(
                    Level::Debug,
                    &format!("Circ {} now in-use. {} delivered bytes.", ev.id, py_int(c.delivered_read_bytes)),
                );
            }
            if purpose == "PATH_BIAS_TESTING" {
                let (op, os) = (old_purpose.as_deref(), old_hs_state.as_deref());
                if op == Some("HS_SERVICE_INTRO") && os == Some("HSSI_CONNECTING") {
                    c.dropped_cells_allowed = 1.0;
                }
                if op == Some("HS_CLIENT_REND") && os == Some("HSCR_CONNECTING") {
                    c.dropped_cells_allowed = 1.0;
                }
                if op == Some("HS_CLIENT_INTRO") && os != Some("HSCI_DONE") {
                    c.dropped_cells_allowed = 1.0;
                }
            } else {
                Self::set_drop_allowance_for_purpose(c, &purpose, hs_state.as_deref());
            }
        }
        sink.log(Level::Debug, &ev.raw);
    }

    pub fn circbw_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        self.circuits_resumed(ev.arrived_at, sink);
        if !self.circs.contains_key(&ev.id) {
            return;
        }
        sink.log(Level::Debug, &ev.raw);
        let num = |k: &str| ev.kw(k).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        let (read, written) = (num("READ"), num("WRITTEN"));
        let (dr, dw, or, ow) = (num("DELIVERED_READ"), num("DELIVERED_WRITTEN"), num("OVERHEAD_READ"), num("OVERHEAD_WRITTEN"));
        if dr + or > read * CELL_DATA_RATE {
            sink.log(Level::Error, &format!("Application read data exceeds cell data:{}", ev.raw));
        }
        if dw + ow > written * CELL_DATA_RATE {
            sink.log(Level::Error, &format!("Application written data exceeds cell data:{}", ev.raw));
        }
        let c = match self.circs.get_mut(&ev.id) {
            Some(c) => c,
            None => return,
        };
        c.read_bytes += read;
        c.sent_bytes += written;
        c.delivered_read_bytes += dr;
        c.overhead_read_bytes += or;
        let snapshot = c.clone();
        Self::check_circuit_limits(&snapshot, sink);
    }

    fn check_circuit_limits(c: &CircStat, sink: &mut dyn Sink) {
        let dropped = c.dropped_read_cells();
        let p = c.purpose.as_deref();
        if dropped > c.dropped_cells_allowed {
            if p == Some("HS_SERVICE_INTRO") && c.hs_state.as_deref() == Some("HSSI_ESTABLISHED") {
                sink.log(
                    Level::Notice,
                    &format!("Tor bug #29699: Got {} dropped cell on circ {} {}.", py_int(dropped), c.circ_id, c.states()),
                );
                sink.close_circuit(&c.circ_id);
            } else if !c.built {
                sink.log(Level::Info, &format!("Tor bug #29927: Got a dropped cell on circ {} {}.", c.circ_id, c.states()));
            } else {
                sink.log(
                    Level::Warn,
                    &format!(
                        "Possible Tor bug, or possible attack if very frequent: Got {} dropped cell on circ {} {}",
                        py_int(dropped),
                        c.circ_id,
                        c.states()
                    ),
                );
                sink.close_circuit(&c.circ_id);
            }
        } else if dropped > 0.0 {
            let bug = if p == Some("PATH_BIAS_TESTING") {
                "29786"
            } else if p == Some("HS_SERVICE_REND") && c.hs_state.as_deref() == Some("HSSR_CONNECTING") {
                "29700"
            } else {
                "29927"
            };
            sink.log(Level::Info, &format!("Tor bug #{bug}: Got a dropped cell on circ {} {}.", c.circ_id, c.states()));
        }
        if CIRC_MAX_MEGABYTES > 0.0 && c.total_bytes() > CIRC_MAX_MEGABYTES * BYTES_PER_MB {
            limit_exceeded(
                sink,
                Level::Notice,
                "CIRC_MAX_MEGABYTES",
                &c.circ_id,
                &py_int_str(c.total_bytes()),
                &py_int_str(CIRC_MAX_MEGABYTES * BYTES_PER_MB),
            );
            sink.close_circuit(&c.circ_id);
        }
        if CIRC_MAX_HSDESC_KILOBYTES > 0.0 && c.is_hsdir && c.total_bytes() > CIRC_MAX_HSDESC_KILOBYTES * BYTES_PER_KB {
            limit_exceeded(
                sink,
                Level::Warn,
                "CIRC_MAX_HSDESC_KILOBYTES",
                &c.circ_id,
                &py_int_str(c.total_bytes()),
                &py_int_str(CIRC_MAX_HSDESC_KILOBYTES * BYTES_PER_KB),
            );
            sink.close_circuit(&c.circ_id);
        }
    }

    pub fn network_liveness_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        sink.log(Level::Debug, &ev.raw);
        match ev.status.as_str() {
            "UP" => self.network_down_since = None,
            "DOWN" => self.network_down_since = Some(ev.arrived_at),
            _ => {}
        }
    }

    fn check_connectivity(&mut self, t: f64, sink: &mut dyn Sink) {
        if self.no_conns_since != 0.0 {
            let secs = py_int(t - self.no_conns_since);
            if CONN_MAX_DISCONNECTED_SECS > 0 && secs >= CONN_MAX_DISCONNECTED_SECS {
                if !self.disconnected_conns || secs % CONN_MAX_DISCONNECTED_SECS == 0 {
                    sink.log(Level::Warn, &format!("We've been disconnected from the Tor network for {secs} seconds!"));
                }
                self.disconnected_conns = true;
            }
        } else if let Some(since) = self.no_circs_since {
            let secs = py_int(t - since);
            if CIRC_MAX_DISCONNECTED_SECS > 0 && secs >= CIRC_MAX_DISCONNECTED_SECS && self.any_circuits_pending(None) {
                if !self.disconnected_circs || secs % CIRC_MAX_DISCONNECTED_SECS == 0 {
                    match self.network_down_since {
                        Some(d) => sink.log(
                            Level::Warn,
                            &format!(
                                "Tor has been disconnected for {} seconds, and failing all circuits for {secs} seconds!",
                                py_int(t - d)
                            ),
                        ),
                        None => sink.log(Level::Notice, &format!("Tor has been failing all circuits for {secs} seconds!")),
                    }
                }
                self.disconnected_circs = true;
            }
        }
    }

    fn check_circ_ages(&mut self, t: f64, sink: &mut dyn Sink) {
        if CIRC_MAX_AGE_HOURS <= 0.0 {
            return;
        }
        let old: Vec<CircStat> =
            self.circ_ids().filter(|c| t - c.created_at > CIRC_MAX_AGE_HOURS * SECS_PER_HOUR).cloned().collect();
        for c in old {
            limit_exceeded(
                sink,
                Level::Notice,
                "CIRC_MAX_AGE_HOURS",
                &c.circ_id,
                &py::float_repr((t - c.created_at) / SECS_PER_HOUR),
                &py_int_str(CIRC_MAX_AGE_HOURS),
            );
            sink.close_circuit(&c.circ_id);
        }
    }

    pub fn bw_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        let t = now();
        self.check_connectivity(ev.arrived_at, sink);
        self.check_circ_ages(t, sink);
    }

    #[cfg(test)]
    pub fn set_created_at(&mut self, id: &str, t: f64) {
        if let Some(c) = self.circs.get_mut(id) {
            c.created_at = t;
        }
    }
}

/// str() of a byte count (Python ints) or of an age in hours (a Python float).
fn py_int_str(x: f64) -> String {
    py_int(x).to_string()
}

fn limit_exceeded(sink: &mut dyn Sink, level: Level, name: &str, id: &str, cur: &str, max: &str) {
    sink.log(level, &format!("Circ {id} exceeded {name}: {cur} > {max}. "));
}

// ───────────────────────────── rendguard ────────────────────────────────────

#[derive(Debug, Clone)]
struct UseCount {
    used: f64,
    weight: f64,
}

#[derive(Default)]
pub struct Rendguard {
    use_counts: BTreeMap<String, UseCount>,
    total_use_counts: f64,
}

/// One relay from GETINFO ns/all.
#[derive(Debug, Clone)]
pub struct Router {
    pub fingerprint: String,
    pub flags: Vec<String>,
    pub measured: f64,
}

impl Rendguard {
    pub fn valid_rend_use(&mut self, r: &str, sink: &mut dyn Sink) -> bool {
        let mut key = r.to_string();
        let mut name = r.to_string();
        if !self.use_counts.contains_key(r) {
            sink.log(Level::Info, &format!("Relay {r} is not in our consensus."));
            name = format!("{r} (not in-consensus)");
            key = NOT_IN_CONSENSUS_ID.to_string();
            self.use_counts.entry(key.clone()).or_insert(UseCount { used: 0.0, weight: 0.0 });
        }
        let total = {
            self.total_use_counts += 1.0;
            self.total_use_counts
        };
        let Some(u) = self.use_counts.get_mut(&key) else { return true };
        u.used += 1.0;
        let rate = 100.0 * u.used / total;
        sink.log(
            Level::Debug,
            &format!(
                "Relay {name} used {} times out of {}, for a use rate of {rate:.6}%. It has a consensus weight of {:.6}%",
                py_int(u.used),
                py_int(total),
                100.0 * u.weight
            ),
        );
        if total >= REND_USE_GLOBAL_START_COUNT
            && u.used >= REND_USE_RELAY_START_COUNT
            && u.used / total > u.weight * REND_USE_MAX_USE_TO_BW_RATIO
        {
            let level = if REND_USE_CLOSE_CIRCUITS_ON_OVERUSE { Level::Notice } else { Level::Warn };
            sink.log(
                level,
                &format!(
                    "Relay {name} used {} times out of {}, for a use rate of {rate:.6}%. This is above its consensus weight of {:.6}%",
                    py_int(u.used),
                    py_int(total),
                    100.0 * u.weight
                ),
            );
            return false;
        }
        true
    }

    /// xfer_use_counts for the Fast+Valid, non-Authority middle-position
    /// generator, after repair_exits.
    pub fn xfer_use_counts(&mut self, routers: &[Router], weights: &BTreeMap<String, f64>, sink: &mut dyn Sink) {
        let mut sorted: Vec<&Router> = routers.iter().collect();
        sorted.sort_by(|a, b| b.measured.partial_cmp(&a.measured).unwrap_or(std::cmp::Ordering::Equal));
        let has = |r: &Router, f: &str| r.flags.iter().any(|x| x == f);
        let rstr: Vec<&Router> =
            sorted.iter().copied().filter(|r| has(r, "Fast") && has(r, "Valid") && !has(r, "Authority")).collect();
        let w = |k: &str| weights.get(k).copied().unwrap_or(0.0) / 10000.0;
        let flag_to_weight = |r: &Router, pos: char| {
            let (g, e) = (has(r, "Guard"), has(r, "Exit"));
            if g && e {
                w(&format!("W{pos}d"))
            } else if e {
                w(&format!("W{pos}e"))
            } else if g {
                w(&format!("W{pos}g"))
            } else {
                w("Wmm")
            }
        };
        let mut node_weights: Vec<f64> = rstr.iter().map(|r| r.measured * flag_to_weight(r, 'm')).collect();
        let weight_total: f64 = node_weights.iter().sum();
        let mut exit_total = 0.0;
        for (i, r) in rstr.iter().enumerate() {
            if has(r, "Exit") {
                node_weights[i] = r.measured * flag_to_weight(r, 'e');
                exit_total += node_weights[i];
            }
        }
        let old = std::mem::take(&mut self.use_counts);
        for r in &sorted {
            self.use_counts.insert(r.fingerprint.clone(), UseCount { used: 0.0, weight: 0.0 });
        }
        let churn = REND_USE_MAX_CONSENSUS_WEIGHT_CHURN / 100.0;
        let mut old = old;
        old.entry(NOT_IN_CONSENSUS_ID.to_string()).or_insert(UseCount { used: 0.0, weight: churn });
        self.use_counts.insert(NOT_IN_CONSENSUS_ID.to_string(), UseCount { used: 0.0, weight: churn });
        for (i, r) in rstr.iter().enumerate() {
            let total = if has(r, "Exit") { exit_total } else { weight_total };
            if let Some(u) = self.use_counts.get_mut(&r.fingerprint) {
                u.weight = if total > 0.0 { node_weights[i] / total } else { 0.0 };
            }
        }
        let scale = self.total_use_counts >= REND_USE_SCALE_AT_COUNT;
        if scale {
            sink.log(
                Level::Info,
                &format!(
                    "Total use counts {} reached the scale count {}. Scaling.",
                    py_int(self.total_use_counts),
                    py_int(REND_USE_SCALE_AT_COUNT)
                ),
            );
        }
        for (k, o) in &old {
            if k != NOT_IN_CONSENSUS_ID && !self.use_counts.contains_key(k) {
                continue;
            }
            if let Some(u) = self.use_counts.get_mut(k) {
                u.used = if scale { o.used / 2.0 } else { o.used };
            }
        }
        self.total_use_counts = self.use_counts.values().map(|u| u.used).sum();
    }

    pub fn circ_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        if ev.status == "BUILT" && ev.purpose() == "HS_SERVICE_REND" && ev.hs_state() == Some("HSSR_CONNECTING") {
            if let Some(last) = ev.path.last() {
                if !self.valid_rend_use(last, sink) && REND_USE_CLOSE_CIRCUITS_ON_OVERUSE {
                    sink.close_circuit(&ev.id);
                }
            }
        }
        sink.log(Level::Debug, &ev.raw);
    }
}

// ─────────────────────── consensus parsing for rendguard ────────────────────

fn b64decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let bytes: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 6) | val(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// GETINFO ns/all body -> routers ("measured" falls back to Bandwidth=).
pub fn parse_ns(body: &str) -> Vec<Router> {
    let mut out: Vec<Router> = Vec::new();
    for line in body.lines() {
        let mut parts = line.split(' ');
        match parts.next() {
            Some("r") => {
                let f: Vec<&str> = line.split(' ').collect();
                if let Some(fp) = f.get(2).and_then(|id| b64decode(id)).filter(|b| b.len() == 20) {
                    out.push(Router {
                        fingerprint: fp.iter().map(|x| format!("{x:02X}")).collect(),
                        flags: vec![],
                        measured: 0.0,
                    });
                }
            }
            Some("s") => {
                if let Some(r) = out.last_mut() {
                    r.flags = parts.map(String::from).collect();
                }
            }
            Some("w") => {
                if let Some(r) = out.last_mut() {
                    let mut bw = None;
                    let mut measured = None;
                    for kv in parts {
                        if let Some(v) = kv.strip_prefix("Bandwidth=") {
                            bw = v.parse::<f64>().ok();
                        } else if let Some(v) = kv.strip_prefix("Measured=") {
                            measured = v.parse::<f64>().ok();
                        }
                    }
                    r.measured = measured.or(bw).unwrap_or(0.0);
                }
            }
            _ => {}
        }
    }
    out
}

/// The `bandwidth-weights` line of a consensus document.
pub fn parse_weights(consensus: &str) -> Option<BTreeMap<String, f64>> {
    let line = consensus.lines().find(|l| l.starts_with("bandwidth-weights "))?;
    Some(
        line.split(' ')
            .skip(1)
            .filter_map(|kv| kv.split_once('=').and_then(|(k, v)| Some((k.to_string(), v.parse::<f64>().ok()?))))
            .collect(),
    )
}

// ─────────────────────────────── control link ───────────────────────────────

struct Link {
    r: BufReader<UnixStream>,
    w: UnixStream,
    pending: Vec<Event>,
}

impl Link {
    fn connect(path: &str) -> std::io::Result<Link> {
        let s = UnixStream::connect(path)?;
        let w = s.try_clone()?;
        Ok(Link { r: BufReader::new(s), w, pending: Vec::new() })
    }

    fn read_line(&mut self) -> std::io::Result<String> {
        let mut buf = Vec::new();
        let n = self.r.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"));
        }
        if buf.len() > 1 << 20 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        let s = String::from_utf8_lossy(&buf).into_owned();
        Ok(s.trim_end_matches(['\r', '\n']).to_string())
    }

    /// Read one complete reply or event. Returns (status code, lines incl. data).
    fn read_message(&mut self) -> std::io::Result<(String, Vec<String>)> {
        let mut lines = Vec::new();
        loop {
            let l = self.read_line()?;
            if l.len() < 4 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short line"));
            }
            let code = l[..3].to_string();
            let sep = l.as_bytes()[3];
            lines.push(l.clone());
            if sep == b'+' {
                loop {
                    let d = self.read_line()?;
                    if d == "." {
                        break;
                    }
                    lines.push(d.strip_prefix('.').filter(|_| d.starts_with("..")).unwrap_or(&d).to_string());
                }
            } else if sep == b' ' {
                return Ok((code, lines));
            }
        }
    }

    /// Send a command; queue any events that arrive before its reply.
    fn command(&mut self, cmd: &str) -> std::io::Result<(String, Vec<String>)> {
        self.w.write_all(format!("{cmd}\r\n").as_bytes())?;
        loop {
            let (code, lines) = self.read_message()?;
            if code == "650" {
                let t = now();
                for l in &lines {
                    if let Some(e) = parse_event(l, t) {
                        self.pending.push(e);
                    }
                }
                continue;
            }
            return Ok((code, lines));
        }
    }

    fn getinfo(&mut self, key: &str) -> std::io::Result<String> {
        let (code, lines) = self.command(&format!("GETINFO {key}"))?;
        if code != "250" {
            return Err(std::io::Error::other(lines.join(" ")));
        }
        // "250-key=value" or "250+key=" followed by data lines, then "250 OK".
        let mut out = Vec::new();
        let mut in_data = false;
        for l in &lines {
            if let Some(v) = l.strip_prefix(&format!("250-{key}=")) {
                return Ok(v.to_string());
            }
            if l.starts_with(&format!("250+{key}=")) {
                in_data = true;
                continue;
            }
            if l.starts_with("250 ") {
                break;
            }
            if in_data {
                out.push(l.clone());
            }
        }
        Ok(out.join("\n"))
    }
}

struct Printer {
    level: Level,
    closes: Vec<String>,
}

impl Sink for Printer {
    fn log(&mut self, level: Level, msg: &str) {
        if level >= self.level {
            println!("{}[{}]: {}", level.name(), asctime(), msg.trim());
        }
    }
    fn close_circuit(&mut self, id: &str) {
        self.closes.push(id.to_string());
    }
}

fn flush_closes(link: &mut Link, p: &mut Printer) -> std::io::Result<()> {
    for id in std::mem::take(&mut p.closes) {
        let (code, lines) = link.command(&format!("CLOSECIRCUIT {id}"))?;
        if code == "250" {
            p.log(Level::Notice, &format!("We force-closed circuit {id}"));
        } else {
            let msg = lines.first().map(|l| l.get(4..).unwrap_or("").to_string()).unwrap_or_default();
            p.log(Level::Info, &format!("Failed to close circuit {id}: {msg}"));
        }
    }
    Ok(())
}

fn new_consensus(link: &mut Link, rg: &mut Rendguard, p: &mut Printer) -> Result<(), String> {
    let ns = link.getinfo("ns/all").map_err(|e| e.to_string())?;
    let data_dir = link
        .command("GETCONF DataDirectory")
        .ok()
        .and_then(|(_, l)| l.first().and_then(|x| x.split_once('=').map(|(_, v)| v.to_string())))
        .unwrap_or_else(|| "/var/lib/tor".into());
    let file = format!("{data_dir}/cached-microdesc-consensus");
    let text = std::fs::read(&file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let weights = parse_weights(&String::from_utf8_lossy(&text)).ok_or_else(|| format!("Cannot read {file}: no bandwidth-weights"))?;
    rg.xfer_use_counts(&parse_ns(&ns), &weights, p);
    Ok(())
}

/// One connection's life. Returns "closed" or "failed: ...", as the addon did.
fn control_loop(sock: &str, rg: &mut Rendguard, p: &mut Printer) -> String {
    let mut link = match Link::connect(sock) {
        Ok(l) => l,
        Err(e) => return format!("failed: {e}"),
    };
    let r = (|| -> Result<(), String> {
        let (code, l) = link.command("AUTHENTICATE").map_err(|e| e.to_string())?;
        if code != "250" {
            p.log(Level::Error, &format!("Unable to authenticate: {}", l.join(" ")));
            std::process::exit(1);
        }
        let version = link.getinfo("version").unwrap_or_default();
        p.log(Level::Notice, &format!("Vanguards (HiddenForge guards {}) connected to Tor {version}", env!("CARGO_PKG_VERSION")));
        if let Err(e) = new_consensus(&mut link, rg, p) {
            p.log(Level::Notice, &format!("Tor needs descriptors: {e}. Trying again..."));
            return Err(format!("failed: {e}"));
        }
        let orconn = link.getinfo("orconn-status").unwrap_or_default();
        let live = link.getinfo("network-liveness").unwrap_or_default();
        let mut bg = Bandguards::new(&orconn, &live, now(), p);
        let (code, l) = link
            .command("SETEVENTS CIRC BW ORCONN NETWORK_LIVENESS CIRC_BW CIRC_MINOR NEWCONSENSUS SIGNAL")
            .map_err(|e| e.to_string())?;
        if code != "250" {
            return Err(format!("failed: SETEVENTS refused: {}", l.join(" ")));
        }
        loop {
            let mut events = std::mem::take(&mut link.pending);
            if events.is_empty() {
                let (code, lines) = match link.read_message() {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                };
                if code != "650" {
                    continue;
                }
                let t = now();
                if lines.first().is_some_and(|l| l.starts_with("650+NEWCONSENSUS")) {
                    if let Err(e) = new_consensus(&mut link, rg, p) {
                        p.log(Level::Notice, &format!("Tor needs descriptors: {e}."));
                    }
                    continue;
                }
                events = lines.iter().filter_map(|l| parse_event(l, t)).collect();
            }
            for ev in events {
                match ev.kind.as_str() {
                    "CIRC" => {
                        rg.circ_event(&ev, p);
                        bg.circ_event(&ev, p);
                    }
                    "CIRC_MINOR" => bg.circ_minor_event(&ev, p),
                    "CIRC_BW" => bg.circbw_event(&ev, p),
                    "BW" => bg.bw_event(&ev, p),
                    "ORCONN" => bg.orconn_event(&ev, p),
                    "NETWORK_LIVENESS" => bg.network_liveness_event(&ev, p),
                    _ => {}
                }
            }
            if flush_closes(&mut link, p).is_err() {
                return Ok(());
            }
        }
    })();
    match r {
        Ok(()) => "closed".into(),
        Err(e) => e,
    }
}

/// `hiddenforge-guards --control_socket S [--state F] [--loglevel L] [--disable_vanguards]`
pub fn main(args: &[String]) -> i32 {
    let mut sock = String::new();
    let mut level = Level::Notice;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--control_socket" => {
                sock = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--loglevel" => {
                let Some(l) = args.get(i + 1).and_then(|s| Level::parse(s)) else {
                    eprintln!("ERROR: Invalid loglevel");
                    return 1;
                };
                level = l;
                i += 1;
            }
            "--state" => i += 1,
            "--disable_vanguards" => {}
            other => {
                eprintln!("hiddenforge-guards: unknown option {other}");
                return 2;
            }
        }
        i += 1;
    }
    if sock.is_empty() {
        eprintln!("hiddenforge-guards: --control_socket is required");
        return 2;
    }
    let mut p = Printer { level, closes: vec![] };
    let mut rg = Rendguard::default();
    let mut reconnects: u64 = 0;
    let mut first_try: Option<f64> = None;
    loop {
        let ret = control_loop(&sock, &mut rg, &mut p);
        let t = now();
        let since = *first_try.get_or_insert(t);
        if ret == "closed" || reconnects % 10 == 0 {
            let lvl = if t - since > CONN_MAX_DISCONNECTED_SECS as f64 { Level::Warn } else { Level::Notice };
            p.log(lvl, &format!("Tor daemon connection {ret}. Trying again..."));
        }
        reconnects += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec {
        logs: Vec<(u8, String)>,
        closes: Vec<String>,
    }
    impl Sink for Rec {
        fn log(&mut self, level: Level, msg: &str) {
            self.logs.push((level as u8, msg.to_string()));
        }
        fn close_circuit(&mut self, id: &str) {
            self.closes.push(id.to_string());
        }
    }
    const G: &str = "$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~guard";
    const R: &str = "$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~rp";

    fn ev(s: &str) -> Event {
        parse_event(s, now()).unwrap()
    }

    #[test]
    fn parses_circ_path_and_keywords() {
        let e = ev(&format!("650 CIRC 7 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"));
        assert_eq!(e.id, "7");
        assert_eq!(e.path.last().unwrap(), &"B".repeat(40));
        assert_eq!(e.hs_state(), Some("HSSR_CONNECTING"));
        assert!(is_fp(&e.path[0]));
    }

    #[test]
    fn dropped_cells_on_established_intro_close_the_circuit() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(&ev(&format!("650 CIRC 5 BUILT {G},{R} PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED")), &mut s);
        // 2 cells read, nothing delivered or overhead: 2 dropped cells > 0 allowed.
        b.circbw_event(&ev("650 CIRC_BW ID=5 READ=1018 WRITTEN=0 TIME=x DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert_eq!(s.closes, vec!["5"]);
    }

    #[test]
    fn one_dropped_cell_allowed_on_connecting_rend() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(&ev(&format!("650 CIRC 6 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING")), &mut s);
        b.circbw_event(&ev("650 CIRC_BW ID=6 READ=509 WRITTEN=0 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert!(s.closes.is_empty());
    }

    #[test]
    fn hsdir_circuit_over_30kb_is_closed() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(&ev(&format!("650 CIRC 8 BUILT {G},{R} PURPOSE=HS_SERVICE_HSDIR")), &mut s);
        b.circbw_event(&ev("650 CIRC_BW ID=8 READ=0 WRITTEN=31745 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert_eq!(s.closes, vec!["8"]);
        assert!(s.logs.iter().any(|(_, m)| m == "Circ 8 exceeded CIRC_MAX_HSDESC_KILOBYTES: 31745 > 30720. "));
    }

    #[test]
    fn circuits_older_than_a_day_are_closed() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(&ev(&format!("650 CIRC 9 EXTENDED {G} PURPOSE=GENERAL")), &mut s);
        b.set_created_at("9", now() - 25.0 * 3600.0);
        b.bw_event(&ev("650 BW 0 0"), &mut s);
        assert_eq!(s.closes, vec!["9"]);
    }

    #[test]
    fn rendguard_closes_overused_rend_point() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        let routers = vec![
            Router { fingerprint: "B".repeat(40), flags: vec!["Fast".into(), "Valid".into()], measured: 1.0 },
            Router { fingerprint: "C".repeat(40), flags: vec!["Fast".into(), "Valid".into()], measured: 999.0 },
        ];
        let w: BTreeMap<String, f64> = [("Wmm".to_string(), 10000.0)].into_iter().collect();
        rg.xfer_use_counts(&routers, &w, &mut s);
        let mut closed = 0;
        for i in 0..1100 {
            let fp = if i % 2 == 0 { "B".repeat(40) } else { "C".repeat(40) };
            let e = ev(&format!("650 CIRC {i} BUILT {G},${fp} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"));
            let before = s.closes.len();
            rg.circ_event(&e, &mut s);
            closed += s.closes.len() - before;
        }
        // B carries 0.1% of the weight but half the use: every use past the
        // global start count is refused.
        assert!(closed > 0);
        assert!(s.closes.iter().all(|id| id.parse::<u32>().unwrap() % 2 == 0));
    }

    #[test]
    fn ns_parsing() {
        let body = "r nick AAAAAAAAAAAAAAAAAAAAAAAAAAA digest 2026-01-01 00:00:00 1.2.3.4 9001 0\ns Fast Running Valid\nw Bandwidth=123";
        let r = parse_ns(body);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].fingerprint, "0".repeat(40));
        assert_eq!(r[0].measured, 123.0);
        assert!(parse_weights("x\nbandwidth-weights Wmm=10000 Wme=0\n").unwrap()["Wmm"] == 10000.0);
    }
}
