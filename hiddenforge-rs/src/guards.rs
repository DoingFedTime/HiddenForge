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

use crate::py;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── bandguards options (Vanguards 0.3.1 defaults) ───────────────────────────
// CIRC_MAX_MEGABYTES defaults to 0 (disabled), so its check is not ported.
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
const MAX_CIRC_DESTROY_LAG_SECS: f64 = 2.0;

// ── rendguard options ───────────────────────────────────────────────────────
const REND_USE_GLOBAL_START_COUNT: f64 = 1000.0;
const REND_USE_SCALE_AT_COUNT: f64 = 20000.0;
const REND_USE_RELAY_START_COUNT: f64 = 100.0;
const REND_USE_MAX_USE_TO_BW_RATIO: f64 = 5.0;
const REND_USE_MAX_CONSENSUS_WEIGHT_CHURN: f64 = 1.0;
const REND_USE_CLOSE_CIRCUITS_ON_OVERUSE: bool = true;
const NOT_IN_CONSENSUS_ID: &str = "NOT_IN_CONSENSUS";

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn asctime() -> String {
    // SAFETY: time(NULL) only returns the clock.
    asctime_at(unsafe { libc::time(std::ptr::null_mut()) })
}

fn asctime_at(t: libc::time_t) -> String {
    // SAFETY: localtime_r/strftime with local buffers.
    unsafe {
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
    let mut ev = Event {
        kind: kind.clone(),
        raw: line.to_string(),
        arrived_at,
        ..Event::default()
    };
    let positional: Vec<&str> = toks
        .iter()
        .copied()
        .take_while(|t| !t.contains('='))
        .collect();
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
            ev.path = vec![if target.starts_with('$') && is_fp(&fp) {
                fp
            } else {
                String::new()
            }];
            ev.status = positional.get(1)?.to_string();
            ev.id = ev.kw("ID").unwrap_or("").to_string();
        }
        "NETWORK_LIVENESS" => ev.status = positional.first()?.to_string(),
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
        self.read_bytes / CELL_PAYLOAD_SIZE
            - (self.delivered_read_bytes + self.overhead_read_bytes) / RELAY_PAYLOAD_SIZE
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
    killed_conn_at: f64,
}

#[derive(Default)]
pub struct Bandguards {
    circs: BTreeMap<String, CircStat>,
    circ_order: Vec<String>,
    live_guard_conns: BTreeMap<String, String>, // conn id -> guard fp
    guards: BTreeMap<String, GuardStat>,
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
        let mut b = Bandguards {
            no_conns_since: t.trunc(),
            max_fake_id: -1,
            ..Bandguards::default()
        };
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
                    sink.log(
                        Level::Notice,
                        &format!(
                            "Reconnected to the Tor network after {} seconds.",
                            py_int(secs)
                        ),
                    );
                }
                self.live_guard_conns.insert(id, guard_fp.clone());
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
                                    &format!(
                                        "Marking possibly destroyed circ {} at {}",
                                        c.circ_id,
                                        py_int(ev.arrived_at)
                                    ),
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
            }
            _ => {}
        }
        sink.log(Level::Info, &ev.raw);
    }

    fn circuit_destroyed(&mut self, ev: &Event, sink: &mut dyn Sink) {
        let guardfp = ev.path.first().cloned().unwrap_or_default();
        let g = self.guards.entry(guardfp.clone()).or_default();
        if ev.arrived_at - g.killed_conn_at <= MAX_CIRC_DESTROY_LAG_SECS {
            g.killed_conn_at = 0.0;
            sink.log(
                Level::Notice,
                &format!("The connection to guard {guardfp} was closed with a live circuit."),
            );
        }
        sink.log(
            Level::Info,
            &format!(
                "The connection to guard {guardfp} was closed with circuit {} on it.",
                ev.id
            ),
        );
    }

    fn any_circuits_pending(&self, except: Option<&str>) -> bool {
        self.circ_ids()
            .any(|c| !c.built && Some(c.circ_id.as_str()) != except)
    }

    fn set_drop_allowance_for_purpose(c: &mut CircStat, purpose: &str, hs_state: Option<&str>) {
        match purpose {
            "HS_SERVICE_REND" => {
                c.dropped_cells_allowed = f64::from(u8::from(hs_state == Some("HSSR_CONNECTING")))
            }
            "HS_CLIENT_REND" => c.dropped_cells_allowed = 1.0,
            "HS_CLIENT_INTRO" => {
                c.dropped_cells_allowed = f64::from(u8::from(hs_state == Some("HSCI_DONE")))
            }
            _ => {}
        }
    }

    pub fn circ_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        if ev.status == "FAILED"
            && self.no_circs_since.is_none()
            && self.any_circuits_pending(Some(&ev.id))
        {
            self.no_circs_since = Some(ev.arrived_at);
        }
        if ev.status == "FAILED" || ev.status == "CLOSED" {
            if let Some(c) = self.circs.get(&ev.id).cloned() {
                if c.in_use {
                    if let Some(pd) = c.possibly_destroyed_at {
                        if ev.arrived_at - pd <= MAX_CIRC_DESTROY_LAG_SECS
                            && ev.kw("REMOTE_REASON") == Some("CHANNEL_CLOSED")
                        {
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
                        &format!(
                            "Circ {} now in-use. {} delivered bytes.",
                            ev.id,
                            py_int(c.delivered_read_bytes)
                        ),
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
            sink.log(
                Level::Notice,
                &format!("Circuit use resumed after {} seconds.", py_int(secs)),
            );
        }
        self.no_circs_since = None;
        self.disconnected_circs = false;
    }

    pub fn circ_minor_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        let Some(c) = self.circs.get_mut(&ev.id) else {
            return;
        };
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
                    &format!(
                        "Circ {} now in-use. {} delivered bytes.",
                        ev.id,
                        py_int(c.delivered_read_bytes)
                    ),
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
        let (dr, dw, or, ow) = (
            num("DELIVERED_READ"),
            num("DELIVERED_WRITTEN"),
            num("OVERHEAD_READ"),
            num("OVERHEAD_WRITTEN"),
        );
        if dr + or > read * CELL_DATA_RATE {
            sink.log(
                Level::Error,
                &format!("Application read data exceeds cell data:{}", ev.raw),
            );
        }
        if dw + ow > written * CELL_DATA_RATE {
            sink.log(
                Level::Error,
                &format!("Application written data exceeds cell data:{}", ev.raw),
            );
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
                    &format!(
                        "Tor bug #29699: Got {} dropped cell on circ {} {}.",
                        py_int(dropped),
                        c.circ_id,
                        c.states()
                    ),
                );
                sink.close_circuit(&c.circ_id);
            } else if !c.built {
                sink.log(
                    Level::Info,
                    &format!(
                        "Tor bug #29927: Got a dropped cell on circ {} {}.",
                        c.circ_id,
                        c.states()
                    ),
                );
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
            } else if p == Some("HS_SERVICE_REND")
                && c.hs_state.as_deref() == Some("HSSR_CONNECTING")
            {
                "29700"
            } else {
                "29927"
            };
            sink.log(
                Level::Info,
                &format!(
                    "Tor bug #{bug}: Got a dropped cell on circ {} {}.",
                    c.circ_id,
                    c.states()
                ),
            );
        }
        if CIRC_MAX_HSDESC_KILOBYTES > 0.0
            && c.is_hsdir
            && c.total_bytes() > CIRC_MAX_HSDESC_KILOBYTES * BYTES_PER_KB
        {
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
                    sink.log(
                        Level::Warn,
                        &format!(
                            "We've been disconnected from the Tor network for {secs} seconds!"
                        ),
                    );
                }
                self.disconnected_conns = true;
            }
        } else if let Some(since) = self.no_circs_since {
            let secs = py_int(t - since);
            if CIRC_MAX_DISCONNECTED_SECS > 0
                && secs >= CIRC_MAX_DISCONNECTED_SECS
                && self.any_circuits_pending(None)
            {
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
        let old: Vec<CircStat> = self
            .circ_ids()
            .filter(|c| t - c.created_at > CIRC_MAX_AGE_HOURS * SECS_PER_HOUR)
            .cloned()
            .collect();
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
    sink.log(
        level,
        &format!("Circ {id} exceeded {name}: {cur} > {max}. "),
    );
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
            self.use_counts.entry(key.clone()).or_insert(UseCount {
                used: 0.0,
                weight: 0.0,
            });
        }
        let total = {
            self.total_use_counts += 1.0;
            self.total_use_counts
        };
        let Some(u) = self.use_counts.get_mut(&key) else {
            return true;
        };
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
            let level = if REND_USE_CLOSE_CIRCUITS_ON_OVERUSE {
                Level::Notice
            } else {
                Level::Warn
            };
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
    pub fn xfer_use_counts(
        &mut self,
        routers: &[Router],
        weights: &BTreeMap<String, f64>,
        sink: &mut dyn Sink,
    ) {
        let mut sorted: Vec<&Router> = routers.iter().collect();
        sorted.sort_by(|a, b| {
            b.measured
                .partial_cmp(&a.measured)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let has = |r: &Router, f: &str| r.flags.iter().any(|x| x == f);
        let rstr: Vec<&Router> = sorted
            .iter()
            .copied()
            .filter(|r| has(r, "Fast") && has(r, "Valid") && !has(r, "Authority"))
            .collect();
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
        let mut node_weights: Vec<f64> = rstr
            .iter()
            .map(|r| r.measured * flag_to_weight(r, 'm'))
            .collect();
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
            self.use_counts.insert(
                r.fingerprint.clone(),
                UseCount {
                    used: 0.0,
                    weight: 0.0,
                },
            );
        }
        let churn = REND_USE_MAX_CONSENSUS_WEIGHT_CHURN / 100.0;
        let mut old = old;
        old.entry(NOT_IN_CONSENSUS_ID.to_string())
            .or_insert(UseCount {
                used: 0.0,
                weight: churn,
            });
        self.use_counts.insert(
            NOT_IN_CONSENSUS_ID.to_string(),
            UseCount {
                used: 0.0,
                weight: churn,
            },
        );
        for (i, r) in rstr.iter().enumerate() {
            let total = if has(r, "Exit") {
                exit_total
            } else {
                weight_total
            };
            if let Some(u) = self.use_counts.get_mut(&r.fingerprint) {
                u.weight = if total > 0.0 {
                    node_weights[i] / total
                } else {
                    0.0
                };
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
            if let Some(u) = self.use_counts.get_mut(k) {
                u.used = if scale { o.used / 2.0 } else { o.used };
            }
        }
        self.total_use_counts = self.use_counts.values().map(|u| u.used).sum();
    }

    pub fn circ_event(&mut self, ev: &Event, sink: &mut dyn Sink) {
        if ev.status == "BUILT"
            && ev.purpose() == "HS_SERVICE_REND"
            && ev.hs_state() == Some("HSSR_CONNECTING")
        {
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
                if let Some(fp) = f
                    .get(2)
                    .and_then(|id| b64decode(id))
                    .filter(|b| b.len() == 20)
                {
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
    let line = consensus
        .lines()
        .find(|l| l.starts_with("bandwidth-weights "))?;
    Some(
        line.split(' ')
            .skip(1)
            .filter_map(|kv| {
                kv.split_once('=')
                    .and_then(|(k, v)| Some((k.to_string(), v.parse::<f64>().ok()?)))
            })
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
        Ok(Link {
            r: BufReader::new(s),
            w,
            pending: Vec::new(),
        })
    }

    fn read_line(&mut self) -> std::io::Result<String> {
        let mut buf = Vec::new();
        // Read at most one byte past the cap, so an endless line is bounded in memory.
        let n = (&mut self.r)
            .take((1 << 20) + 1)
            .read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ));
        }
        if buf.len() > 1 << 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short line",
                ));
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
                    lines.push(
                        d.strip_prefix('.')
                            .filter(|_| d.starts_with(".."))
                            .unwrap_or(&d)
                            .to_string(),
                    );
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

impl Printer {
    /// The line to print for one message, or None when it is below the level.
    fn render(&self, level: Level, msg: &str, stamp: impl FnOnce() -> String) -> Option<String> {
        (level >= self.level).then(|| format!("{}[{}]: {}", level.name(), stamp(), msg.trim()))
    }
}

impl Sink for Printer {
    fn log(&mut self, level: Level, msg: &str) {
        if let Some(line) = self.render(level, msg, asctime) {
            println!("{line}");
        }
    }
    fn close_circuit(&mut self, id: &str) {
        self.closes.push(id.to_string());
    }
}

fn flush_closes(link: &mut Link, closes: Vec<String>, sink: &mut dyn Sink) -> std::io::Result<()> {
    for id in closes {
        let (code, lines) = link.command(&format!("CLOSECIRCUIT {id}"))?;
        if code == "250" {
            sink.log(Level::Notice, &format!("We force-closed circuit {id}"));
        } else {
            let msg = lines
                .first()
                .map(|l| l.get(4..).unwrap_or("").to_string())
                .unwrap_or_default();
            sink.log(Level::Info, &format!("Failed to close circuit {id}: {msg}"));
        }
    }
    Ok(())
}

/// Full vanguards: the layers and where they persist.
pub struct Full {
    pub layers: crate::vanguards::Layers,
    pub state: String,
}

impl Full {
    fn apply(&self, link: &mut Link, p: &mut Printer) -> Result<(), String> {
        let (code, l) = link
            .command(&self.layers.setconf())
            .map_err(|e| e.to_string())?;
        if code != "250" {
            p.log(
                Level::Error,
                &format!(
                    "Tor refused the vanguard pins ({}). Full vanguards need TOR_SANDBOX=0.",
                    l.join(" ")
                ),
            );
            std::process::exit(1);
        }
        Ok(())
    }
}

fn new_consensus(
    link: &mut Link,
    rg: &mut Rendguard,
    full: &mut Option<Full>,
    p: &mut Printer,
) -> Result<(), String> {
    let ns = link.getinfo("ns/all").map_err(|e| e.to_string())?;
    let data_dir = link
        .command("GETCONF DataDirectory")
        .ok()
        .and_then(|(_, l)| {
            l.first()
                .and_then(|x| x.split_once('=').map(|(_, v)| v.to_string()))
        })
        .unwrap_or_else(|| "/var/lib/tor".into());
    let file = format!("{data_dir}/cached-microdesc-consensus");
    let text = std::fs::read(&file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let weights = parse_weights(&String::from_utf8_lossy(&text))
        .ok_or_else(|| format!("Cannot read {file}: no bandwidth-weights"))?;
    let routers = parse_ns(&ns);
    if let Some(f) = full.as_mut() {
        let before = (
            crate::vanguards::Layers::guardset(&f.layers.layer2),
            crate::vanguards::Layers::guardset(&f.layers.layer3),
        );
        if !f.layers.update(
            &routers,
            &weights,
            now(),
            &mut crate::vanguards::csprng_unit,
        ) {
            return Err("no relays to choose vanguards from".into());
        }
        f.apply(link, p)?;
        let after = (
            crate::vanguards::Layers::guardset(&f.layers.layer2),
            crate::vanguards::Layers::guardset(&f.layers.layer3),
        );
        if before != after {
            p.log(
                Level::Notice,
                &format!(
                    "Full vanguards: {} layer-2 and {} layer-3 guards pinned.",
                    f.layers.layer2.len(),
                    f.layers.layer3.len()
                ),
            );
        }
        if let Err(e) = f.layers.save(&f.state) {
            p.log(Level::Error, &e);
            std::process::exit(1);
        }
    }
    rg.xfer_use_counts(&routers, &weights, p);
    Ok(())
}

/// Hand one event to the guards that subscribe to its kind.
fn dispatch_event(ev: &Event, rg: &mut Rendguard, bg: &mut Bandguards, sink: &mut dyn Sink) {
    match ev.kind.as_str() {
        "CIRC" => {
            rg.circ_event(ev, sink);
            bg.circ_event(ev, sink);
        }
        "CIRC_MINOR" => bg.circ_minor_event(ev, sink),
        "CIRC_BW" => bg.circbw_event(ev, sink),
        "BW" => bg.bw_event(ev, sink),
        "ORCONN" => bg.orconn_event(ev, sink),
        "NETWORK_LIVENESS" => bg.network_liveness_event(ev, sink),
        _ => {}
    }
}

/// The reconnect log policy of the addon's main loop: every `closed` and every
/// tenth failure is logged, at WARN once the first attempt is over
/// CONN_MAX_DISCONNECTED_SECS old, else at NOTICE. `first_try` is never reset,
/// as in Vanguards 0.3.1.
#[derive(Default)]
struct Reconnects {
    count: u64,
    first_try: Option<f64>,
}

impl Reconnects {
    /// Record that a connection ended with `ret` at time `t`; the level to log it at, if any.
    fn ended(&mut self, ret: &str, t: f64) -> Option<Level> {
        let since = *self.first_try.get_or_insert(t);
        let level = if t - since > CONN_MAX_DISCONNECTED_SECS as f64 {
            Level::Warn
        } else {
            Level::Notice
        };
        let level = (ret == "closed" || self.count % 10 == 0).then_some(level);
        self.count += 1;
        level
    }
}

/// One connection's life. Returns "closed" or "failed: ...", as the addon did.
fn control_loop(
    sock: &str,
    rg: &mut Rendguard,
    full: &mut Option<Full>,
    p: &mut Printer,
) -> String {
    let mut link = match Link::connect(sock) {
        Ok(l) => l,
        Err(e) => return format!("failed: {e}"),
    };
    let r = (|| -> Result<(), String> {
        let (code, l) = link.command("AUTHENTICATE").map_err(|e| e.to_string())?;
        if code != "250" {
            p.log(
                Level::Error,
                &format!("Unable to authenticate: {}", l.join(" ")),
            );
            std::process::exit(1);
        }
        let version = link.getinfo("version").unwrap_or_default();
        p.log(
            Level::Notice,
            &format!(
                "Vanguards (HiddenForge guards {}) connected to Tor {version}",
                env!("CARGO_PKG_VERSION")
            ),
        );
        if let Err(e) = new_consensus(&mut link, rg, full, p) {
            p.log(
                Level::Notice,
                &format!("Tor needs descriptors: {e}. Trying again..."),
            );
            return Err(format!("failed: {e}"));
        }
        let orconn = link.getinfo("orconn-status").unwrap_or_default();
        let live = link.getinfo("network-liveness").unwrap_or_default();
        let mut bg = Bandguards::new(&orconn, &live, now(), p);
        let (code, l) = link
            .command(
                "SETEVENTS CIRC BW ORCONN NETWORK_LIVENESS CIRC_BW CIRC_MINOR NEWCONSENSUS SIGNAL",
            )
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
                if lines
                    .first()
                    .is_some_and(|l| l.starts_with("650+NEWCONSENSUS"))
                {
                    if let Err(e) = new_consensus(&mut link, rg, full, p) {
                        p.log(Level::Notice, &format!("Tor needs descriptors: {e}."));
                    }
                    continue;
                }
                // A SIGHUP makes Tor re-read its torrc, which drops the pins.
                if lines.iter().any(|l| l.starts_with("650 SIGNAL RELOAD")) {
                    if let Some(f) = full.as_ref() {
                        p.log(Level::Notice, "Tor got SIGHUP. Reapplying vanguards.");
                        f.apply(&mut link, p).map_err(|e| format!("failed: {e}"))?;
                    }
                }
                events = lines.iter().filter_map(|l| parse_event(l, t)).collect();
            }
            for ev in events {
                dispatch_event(&ev, rg, &mut bg, p);
            }
            let closes = std::mem::take(&mut p.closes);
            if flush_closes(&mut link, closes, p).is_err() {
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
    let mut state = String::new();
    let mut disable = false;
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
            "--state" => {
                state = args.get(i + 1).cloned().unwrap_or_default();
                i += 1;
            }
            "--disable_vanguards" => disable = true,
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
    let mut p = Printer {
        level,
        closes: vec![],
    };
    let mut rg = Rendguard::default();
    let mut full = if disable {
        None
    } else {
        if state.is_empty() {
            eprintln!("hiddenforge-guards: full vanguards need --state <file>");
            return 2;
        }
        let layers = crate::vanguards::Layers::load(&state);
        p.log(
            Level::Notice,
            &format!(
                "Full vanguards enabled: {} layer-2 and {} layer-3 guards restored from {state}.",
                layers.layer2.len(),
                layers.layer3.len()
            ),
        );
        Some(Full { layers, state })
    };
    let mut reconnects = Reconnects::default();
    loop {
        let ret = control_loop(&sock, &mut rg, &mut full, &mut p);
        if let Some(lvl) = reconnects.ended(&ret, now()) {
            p.log(
                lvl,
                &format!("Tor daemon connection {ret}. Trying again..."),
            );
        }
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

    fn link_fed(bytes: Vec<u8>) -> (Link, std::thread::JoinHandle<()>) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let feeder = std::thread::spawn(move || {
            use std::io::Write;
            let mut t = theirs;
            let _ = t.write_all(&bytes);
            // Hold the connection open, the way a stalled peer would.
            std::thread::sleep(std::time::Duration::from_secs(5));
        });
        let link = Link {
            w: ours.try_clone().unwrap(),
            r: BufReader::new(ours),
            pending: Vec::new(),
        };
        (link, feeder)
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_line_stops_at_the_cap_without_waiting_for_a_newline() {
        // 1 MiB + 1 bytes and no newline: the cap must trip on what has arrived,
        // not after buffering an unbounded line.
        let (mut link, _feeder) = link_fed(vec![b'a'; (1 << 20) + 1]);
        let e = link.read_line().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_line_accepts_a_line_exactly_at_the_cap() {
        let mut line = vec![b'a'; (1 << 20) - 2];
        line.extend_from_slice(b"\r\n");
        let (mut link, _feeder) = link_fed(line);
        assert_eq!(link.read_line().unwrap().len(), (1 << 20) - 2);
    }

    #[test]
    fn parses_circ_path_and_keywords() {
        let e = ev(&format!(
            "650 CIRC 7 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"
        ));
        assert_eq!(e.id, "7");
        assert_eq!(e.path.last().unwrap(), &"B".repeat(40));
        assert_eq!(e.hs_state(), Some("HSSR_CONNECTING"));
        assert!(is_fp(&e.path[0]));
    }

    #[test]
    fn dropped_cells_on_established_intro_close_the_circuit() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(
            &ev(&format!(
                "650 CIRC 5 BUILT {G},{R} PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED"
            )),
            &mut s,
        );
        // 2 cells read, nothing delivered or overhead: 2 dropped cells > 0 allowed.
        b.circbw_event(&ev("650 CIRC_BW ID=5 READ=1018 WRITTEN=0 TIME=x DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert_eq!(s.closes, vec!["5"]);
    }

    #[test]
    fn one_dropped_cell_allowed_on_connecting_rend() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(
            &ev(&format!(
                "650 CIRC 6 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"
            )),
            &mut s,
        );
        b.circbw_event(&ev("650 CIRC_BW ID=6 READ=509 WRITTEN=0 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert!(s.closes.is_empty());
    }

    #[test]
    fn hsdir_circuit_over_30kb_is_closed() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(
            &ev(&format!(
                "650 CIRC 8 BUILT {G},{R} PURPOSE=HS_SERVICE_HSDIR"
            )),
            &mut s,
        );
        b.circbw_event(&ev("650 CIRC_BW ID=8 READ=0 WRITTEN=31745 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0"), &mut s);
        assert_eq!(s.closes, vec!["8"]);
        assert!(s
            .logs
            .iter()
            .any(|(_, m)| m == "Circ 8 exceeded CIRC_MAX_HSDESC_KILOBYTES: 31745 > 30720. "));
    }

    #[test]
    fn circuits_older_than_a_day_are_closed() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", now(), &mut s);
        b.circ_event(
            &ev(&format!("650 CIRC 9 EXTENDED {G} PURPOSE=GENERAL")),
            &mut s,
        );
        b.set_created_at("9", now() - 25.0 * 3600.0);
        b.bw_event(&ev("650 BW 0 0"), &mut s);
        assert_eq!(s.closes, vec!["9"]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "too slow under miri")]
    fn rendguard_closes_overused_rend_point() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        let routers = vec![
            Router {
                fingerprint: "B".repeat(40),
                flags: vec!["Fast".into(), "Valid".into()],
                measured: 1.0,
            },
            Router {
                fingerprint: "C".repeat(40),
                flags: vec!["Fast".into(), "Valid".into()],
                measured: 999.0,
            },
        ];
        let w: BTreeMap<String, f64> = [("Wmm".to_string(), 10000.0)].into_iter().collect();
        rg.xfer_use_counts(&routers, &w, &mut s);
        let mut closed = 0;
        for i in 0..1100 {
            let fp = if i % 2 == 0 {
                "B".repeat(40)
            } else {
                "C".repeat(40)
            };
            let e = ev(&format!(
                "650 CIRC {i} BUILT {G},${fp} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"
            ));
            let before = s.closes.len();
            rg.circ_event(&e, &mut s);
            closed += s.closes.len() - before;
        }
        // B carries 0.1% of the weight but half the use: every use past the
        // global start count is refused.
        assert!(closed > 0);
        assert!(s
            .closes
            .iter()
            .all(|id| id.parse::<u32>().unwrap() % 2 == 0));
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

    // ── helpers shared by the tests below ───────────────────────────────────

    const GC: &str = "$CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC~gc";

    fn fp(c: char) -> String {
        c.to_string().repeat(40)
    }

    fn evt(s: &str, at: f64) -> Event {
        parse_event(s, at).unwrap()
    }

    fn l(level: Level, msg: &str) -> (u8, String) {
        (level as u8, msg.to_string())
    }

    impl Rec {
        fn has(&self, level: Level, msg: &str) -> bool {
            self.logs
                .iter()
                .any(|(lv, m)| *lv == level as u8 && m == msg)
        }
        fn count_starting(&self, prefix: &str) -> usize {
            self.logs
                .iter()
                .filter(|(_, m)| m.starts_with(prefix))
                .count()
        }
        /// Everything at NOTICE or above, in order.
        fn loud(&self) -> Vec<(u8, String)> {
            self.logs
                .iter()
                .filter(|(lv, _)| *lv >= Level::Notice as u8)
                .cloned()
                .collect()
        }
        fn take(&mut self) -> Vec<(u8, String)> {
            std::mem::take(&mut self.logs)
        }
    }

    /// Run a body on its own thread and fail if it has not finished in time.
    /// The orconn fix-up loop walks down from the newest fake id; a broken
    /// step would spin for ever instead of failing.
    fn within<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        let h = std::thread::spawn(body);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !h.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the body did not finish in 20 s (a loop that never ends?)"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
    }

    fn beat(b: &mut Bandguards, s: &mut Rec, at: f64) -> Vec<(u8, String)> {
        s.logs.clear();
        b.bw_event(&evt("650 BW 1 1", at), s);
        s.take()
    }

    fn link_pair() -> (Link, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        theirs
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let link = Link {
            w: ours.try_clone().unwrap(),
            r: BufReader::new(ours),
            pending: Vec::new(),
        };
        (link, theirs)
    }

    // ── G6: pure helpers ────────────────────────────────────────────────────

    #[test]
    fn is_fp_wants_exactly_forty_hex_digits() {
        assert!(is_fp(&"0123456789abcdefABCDEF0123456789abcdefAB"[..40]));
        assert!(is_fp(&fp('A')));
        assert!(!is_fp(&fp('A')[..39]));
        assert!(!is_fp(&format!("{}A", fp('A'))));
        assert!(!is_fp(&format!("{}G", &fp('A')[..39])));
        assert!(!is_fp(""));
        assert!(!is_fp(&"g".repeat(40)));
    }

    #[test]
    fn fingerprint_cuts_the_dollar_and_the_nickname() {
        for e in [
            format!("${}~nick", fp('A')),
            format!("${}=nick", fp('A')),
            format!("${}", fp('A')),
            fp('A'),
        ] {
            assert_eq!(fingerprint(&e), fp('A'), "{e}");
        }
    }

    #[test]
    fn level_names_parse_and_order() {
        let all = [
            ("DEBUG", Level::Debug),
            ("INFO", Level::Info),
            ("NOTICE", Level::Notice),
            ("WARN", Level::Warn),
            ("ERROR", Level::Error),
        ];
        for (name, lv) in all {
            assert_eq!(Level::parse(name), Some(lv), "{name}");
            assert_eq!(lv.name(), name);
        }
        for bad in ["", "notice", "WARNING", "NONE", "TRACE"] {
            assert_eq!(Level::parse(bad), None, "{bad}");
        }
        // The addon's numeric order: DEBUG < INFO < NOTICE (INFO+5) < WARN < ERROR.
        assert_eq!(all.map(|(_, lv)| lv as u8), [10, 20, 25, 30, 40]);
        assert!(all.windows(2).all(|w| w[0].1 < w[1].1));
    }

    #[test]
    fn now_is_the_wall_clock() {
        let std_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let ours = now();
        assert!(ours > 1.7e9, "{ours}");
        assert!((ours - std_now).abs() < 5.0, "{ours} vs {std_now}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn asctime_is_the_addons_log_stamp() {
        // %a %b %d %H:%M:%S %Y, as logger.py formats it; %d is zero padded.
        // 1_700_000_000 is Tue 2023-11-14 22:13:20 UTC, so any local zone
        // lands on Nov 14 or 15 with the seconds field untouched.
        let s = asctime_at(1_700_000_000);
        let t: Vec<&str> = s.split(' ').collect();
        assert_eq!(t.len(), 5, "{s}");
        assert!(["Tue", "Wed"].contains(&t[0]), "{s}");
        assert_eq!(t[1], "Nov", "{s}");
        assert!(["14", "15"].contains(&t[2]), "{s}");
        assert_eq!(t[3].len(), 8, "{s}");
        assert!(t[3].ends_with(":20"), "{s}");
        assert_eq!(t[3].as_bytes()[2], b':', "{s}");
        assert_eq!(t[4], "2023", "{s}");
        // 1_699_000_000 is 2023-11-03 08:26:40 UTC: the day is 02, 03 or 04.
        let d = asctime_at(1_699_000_000);
        let day = d.split(' ').nth(2).unwrap();
        assert!(["02", "03", "04"].contains(&day), "{d}");
        // The real clock gives a stamp of the same shape.
        assert_eq!(asctime().split(' ').count(), 5);
    }

    #[test]
    fn b64decode_follows_the_standard_alphabet() {
        assert_eq!(b64decode("+/8="), Some(vec![0xFB, 0xFF]));
        assert_eq!(b64decode("Zm9vYg=="), Some(b"foob".to_vec()));
        assert_eq!(b64decode("Zm9v"), Some(b"foo".to_vec()));
        assert_eq!(b64decode("AAAA"), Some(vec![0, 0, 0]));
        assert_eq!(b64decode("/+/+"), Some(vec![0xFF, 0xEF, 0xFE]));
        assert_eq!(b64decode(""), Some(vec![]));
        for bad in ["-_8=", "Zm9v!", "Zm 9v", "Zm9v\n"] {
            assert_eq!(b64decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn parse_event_keeps_the_line_and_its_arrival_time() {
        let line = format!("650 CIRC 7 BUILT {G},{R} PURPOSE=GENERAL");
        let e = evt(&line, 1234.5);
        assert_eq!(e.raw, line);
        assert_eq!(e.arrived_at, 1234.5);
        assert_eq!(e.kind, "CIRC");
        assert_eq!(e.status, "BUILT");
        assert_eq!(e.path, vec![fp('A'), fp('B')]);
        assert_eq!(e.kw("PURPOSE"), Some("GENERAL"));
        assert_eq!(e.purpose(), "GENERAL");
    }

    #[test]
    fn parse_event_reads_orconn_and_liveness() {
        let e = evt(&format!("650 ORCONN {G} CLOSED REASON=DONE ID=42"), 1.0);
        assert_eq!(
            (e.kind.as_str(), e.id.as_str(), e.status.as_str()),
            ("ORCONN", "42", "CLOSED")
        );
        assert_eq!(e.path, vec![fp('A')]);
        // No ID keyword: empty id.
        assert_eq!(evt(&format!("650 ORCONN {G} CONNECTED"), 1.0).id, "");
        // A relay given by address, a short fingerprint or no '$': no guard.
        let bad_targets = [
            "1.2.3.4:9001".to_string(),
            "$ABCD~short".to_string(),
            fp('A'),
            format!("${}Z", &fp('A')[..39]),
        ];
        for target in bad_targets {
            let e = evt(&format!("650 ORCONN {target} CONNECTED ID=1"), 1.0);
            assert_eq!(e.path, vec![String::new()], "{target}");
        }
        let e = evt("650 NETWORK_LIVENESS DOWN", 1.0);
        assert_eq!(
            (e.kind.as_str(), e.status.as_str()),
            ("NETWORK_LIVENESS", "DOWN")
        );
        assert!(parse_event("650 NETWORK_LIVENESS", 1.0).is_none());
        assert!(parse_event("650 ORCONN", 1.0).is_none());
        assert!(parse_event(&format!("650 ORCONN {G}"), 1.0).is_none());
        let e = evt("650 CIRC_BW ID=9 READ=1 WRITTEN=2", 1.0);
        assert_eq!((e.kind.as_str(), e.id.as_str()), ("CIRC_BW", "9"));
        assert!(parse_event("650 CIRC_BW READ=1", 1.0).is_none());
        let e = evt("650 BW 5 6", 1.0);
        assert_eq!(
            (e.kind.as_str(), e.id.as_str(), e.status.as_str()),
            ("BW", "", "")
        );
        // Not an event line, or a CIRC without id and status.
        assert!(parse_event("250 OK", 1.0).is_none());
        assert!(parse_event("650", 1.0).is_none());
        assert!(parse_event("650 CIRC 7", 1.0).is_none());
        assert!(parse_event("650 CIRC_MINOR", 1.0).is_none());
    }

    #[test]
    fn printer_prints_from_its_level_up() {
        let p = Printer {
            level: Level::Warn,
            closes: vec![],
        };
        let stamp = || "STAMP".to_string();
        assert_eq!(
            p.render(Level::Warn, "x", stamp).as_deref(),
            Some("WARN[STAMP]: x")
        );
        assert_eq!(
            p.render(Level::Error, "  padded \r\n", stamp).as_deref(),
            Some("ERROR[STAMP]: padded")
        );
        for below in [Level::Debug, Level::Info, Level::Notice] {
            assert_eq!(p.render(below, "x", stamp), None);
        }
        let d = Printer {
            level: Level::Debug,
            closes: vec![],
        };
        assert_eq!(
            d.render(Level::Notice, "n", stamp).as_deref(),
            Some("NOTICE[STAMP]: n")
        );
        assert_eq!(
            d.render(Level::Info, "i", stamp).as_deref(),
            Some("INFO[STAMP]: i")
        );
        assert_eq!(
            d.render(Level::Debug, "d", stamp).as_deref(),
            Some("DEBUG[STAMP]: d")
        );
        // A message below the level never asks for the clock.
        assert_eq!(p.render(Level::Info, "x", || panic!("stamped")), None);
        // The Sink side records closes in order.
        let mut p = p;
        p.close_circuit("4");
        p.close_circuit("2");
        assert_eq!(p.closes, vec!["4", "2"]);
    }

    // ── G10: the reconnect log policy ───────────────────────────────────────

    #[test]
    fn reconnect_log_every_close_and_every_tenth_failure() {
        let mut r = Reconnects::default();
        // t stays inside the 15 s grace, so everything logged is NOTICE.
        let mut got = Vec::new();
        for i in 0..25 {
            got.push(r.ended("failed: refused", 1000.0 + f64::from(i % 5)));
        }
        let logged: Vec<usize> = got
            .iter()
            .enumerate()
            .filter_map(|(i, l)| l.map(|_| i))
            .collect();
        assert_eq!(logged, vec![0, 10, 20]);
        assert!(got.iter().flatten().all(|l| *l == Level::Notice));
        assert_eq!(r.count, 25);
        // A clean close is always logged, whatever the counter says.
        for _ in 0..3 {
            assert_eq!(r.ended("closed", 1001.0), Some(Level::Notice));
        }
        assert_eq!(r.count, 28);
    }

    #[test]
    fn reconnect_log_goes_to_warn_after_fifteen_seconds() {
        // (first attempt, now) -> level; the age is `now - first`, strictly over 15 s.
        for (first, t, want) in [
            (1000.0, 1000.0, Level::Notice),
            (1000.0, 1010.0, Level::Notice),
            (1000.0, 1015.0, Level::Notice),
            (1000.0, 1015.5, Level::Warn),
            (1000.0, 1100.0, Level::Warn),
            (1.0, 17.0, Level::Warn),
        ] {
            let mut r = Reconnects::default();
            assert_eq!(r.ended("closed", first), Some(Level::Notice));
            assert_eq!(r.ended("closed", t), Some(want), "{first} -> {t}");
        }
        // first_try is set once and never reset, as in Vanguards 0.3.1: a
        // session that ended long ago still makes the next report a WARN.
        let mut r = Reconnects::default();
        r.ended("closed", 1000.0);
        r.ended("closed", 5000.0);
        assert_eq!(r.first_try, Some(1000.0));
    }

    // ── G1: connection loss ─────────────────────────────────────────────────

    #[test]
    fn new_pins_the_clocks_and_numbers_the_listed_conns() {
        let mut s = Rec::default();
        let b = Bandguards::new("", "up", 1234.7, &mut s);
        assert_eq!(b.no_conns_since, 1234.0);
        assert_eq!(b.network_down_since, None);
        assert_eq!(b.max_fake_id, -1);
        assert!(s.logs.is_empty());
        for liveness in ["down", "", "unknown"] {
            let b = Bandguards::new("", liveness, 1234.7, &mut s);
            assert_eq!(b.network_down_since, Some(1234.0), "{liveness:?}");
        }
        // Blank lines do not take a fake id; each conn does, from 0.
        let two = format!("{G} CONNECTED\n\n{R} CONNECTED\n");
        let b = Bandguards::new(&two, "up", 50.0, &mut s);
        assert_eq!(b.max_fake_id, 1);
        assert_eq!(
            b.live_guard_conns,
            BTreeMap::from([("0".to_string(), fp('A')), ("1".to_string(), fp('B'))])
        );
        assert_eq!(b.no_conns_since, 0.0);
        assert!(!b.disconnected_conns);
        assert!(s.logs.iter().all(|(lv, _)| *lv == Level::Info as u8));
    }

    #[test]
    fn connection_loss_timeline() {
        let mut s = Rec::default();
        let mut b = Bandguards::new(&format!("{G} CONNECTED"), "up", 900.0, &mut s);
        b.orconn_event(
            &evt(&format!("650 ORCONN {G} CLOSED REASON=DONE ID=0"), 1000.0),
            &mut s,
        );
        assert_eq!(b.no_conns_since, 1000.0);
        let warn = |n: u32| {
            vec![l(
                Level::Warn,
                &format!("We've been disconnected from the Tor network for {n} seconds!"),
            )]
        };
        // Silent until 15 s, then one WARN, then one every 15 s.
        assert!(beat(&mut b, &mut s, 1014.0).is_empty());
        assert_eq!(beat(&mut b, &mut s, 1017.0), warn(17));
        assert!(b.disconnected_conns);
        assert!(beat(&mut b, &mut s, 1018.0).is_empty());
        assert!(beat(&mut b, &mut s, 1029.0).is_empty());
        assert_eq!(beat(&mut b, &mut s, 1030.0), warn(30));
        assert!(beat(&mut b, &mut s, 1031.0).is_empty());
        assert_eq!(beat(&mut b, &mut s, 1045.0), warn(45));
        // Back: one NOTICE with the whole outage, and the clock is cleared.
        b.orconn_event(
            &evt(&format!("650 ORCONN {G} CONNECTED ID=7"), 1046.9),
            &mut s,
        );
        assert!(s.has(
            Level::Notice,
            "Reconnected to the Tor network after 46 seconds."
        ));
        assert_eq!(b.no_conns_since, 0.0);
        assert!(!b.disconnected_conns);
        assert!(beat(&mut b, &mut s, 1100.0).is_empty());
    }

    #[test]
    fn connection_loss_counts_whole_seconds() {
        let mut s = Rec::default();
        let mut b = Bandguards::new(&format!("{G} CONNECTED"), "up", 900.0, &mut s);
        b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=0"), 1000.0), &mut s);
        assert!(beat(&mut b, &mut s, 1014.9).is_empty());
        let got = beat(&mut b, &mut s, 1015.9);
        assert_eq!(
            got,
            vec![l(
                Level::Warn,
                "We've been disconnected from the Tor network for 15 seconds!"
            )]
        );
    }

    #[test]
    fn connected_without_an_outage_logs_no_notice() {
        let mut s = Rec::default();
        let mut b = Bandguards::new("", "up", 900.0, &mut s);
        b.orconn_event(
            &evt(&format!("650 ORCONN {G} CONNECTED ID=3"), 905.0),
            &mut s,
        );
        assert!(s.loud().is_empty());
        assert_eq!(b.no_conns_since, 0.0);
        assert!(s.has(Level::Info, &format!("650 ORCONN {G} CONNECTED ID=3")));
    }

    #[test]
    fn closing_one_of_two_conns_keeps_connectivity() {
        within(|| {
            let mut s = Rec::default();
            let two = format!("{G} CONNECTED\n{R} CONNECTED");
            let mut b = Bandguards::new(&two, "up", 900.0, &mut s);
            for status in ["CLOSED", "FAILED"] {
                b.live_guard_conns.insert("5".into(), fp('A'));
                b.orconn_event(
                    &evt(&format!("650 ORCONN {G} {status} ID=5"), 1000.0),
                    &mut s,
                );
                assert!(!b.live_guard_conns.contains_key("5"), "{status}");
                assert_eq!(b.no_conns_since, 0.0, "{status}");
            }
            // An id and guard nobody knows changes nothing.
            let before = b.live_guard_conns.clone();
            b.orconn_event(
                &evt(&format!("650 ORCONN {GC} CLOSED ID=77"), 1001.0),
                &mut s,
            );
            assert_eq!(b.live_guard_conns, before);
            assert_eq!(b.no_conns_since, 0.0);
            // The last one going makes the outage start.
            b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=0"), 1002.0), &mut s);
            assert_eq!(b.no_conns_since, 0.0);
            b.orconn_event(&evt(&format!("650 ORCONN {R} CLOSED ID=1"), 1003.0), &mut s);
            assert!(b.live_guard_conns.is_empty());
            assert_eq!(b.no_conns_since, 1003.0);
            // Every orconn event is echoed at INFO, and unknown statuses do nothing more.
            let launched = format!("650 ORCONN {G} LAUNCHED ID=9");
            b.orconn_event(&evt(&launched, 1004.0), &mut s);
            assert!(s.has(Level::Info, &launched));
            assert_eq!(b.no_conns_since, 1003.0);
            assert!(b.live_guard_conns.is_empty());
        });
    }

    #[test]
    fn closed_orconn_maps_onto_the_lowest_fake_id_of_its_guard() {
        within(|| {
            let mut s = Rec::default();
            let three = format!("{G} CONNECTED\n{G} CONNECTED\n{R} CONNECTED");
            let mut b = Bandguards::new(&three, "up", 900.0, &mut s);
            assert_eq!(b.max_fake_id, 2);
            let keys =
                |b: &Bandguards| -> Vec<String> { b.live_guard_conns.keys().cloned().collect() };
            b.orconn_event(
                &evt(&format!("650 ORCONN {G} CLOSED ID=99"), 1000.0),
                &mut s,
            );
            assert_eq!(keys(&b), vec!["1", "2"]);
            b.orconn_event(
                &evt(&format!("650 ORCONN {G} FAILED ID=98"), 1001.0),
                &mut s,
            );
            assert_eq!(keys(&b), vec!["2"]);
            b.orconn_event(
                &evt(&format!("650 ORCONN {R} CLOSED ID=97"), 1002.0),
                &mut s,
            );
            assert!(keys(&b).is_empty());
            assert_eq!(b.no_conns_since, 1002.0);
        });
    }

    #[test]
    fn closed_orconn_with_a_known_id_is_not_remapped() {
        within(|| {
            let mut s = Rec::default();
            let mut b = Bandguards::new(&format!("{G} CONNECTED"), "up", 900.0, &mut s);
            b.orconn_event(
                &evt(&format!("650 ORCONN {G} CONNECTED ID=7"), 901.0),
                &mut s,
            );
            assert_eq!(b.live_guard_conns.len(), 2);
            b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=7"), 902.0), &mut s);
            assert_eq!(
                b.live_guard_conns,
                BTreeMap::from([("0".to_string(), fp('A'))])
            );
        });
    }

    // ── G2: circuit failure ─────────────────────────────────────────────────

    fn connected() -> (Bandguards, Rec) {
        let mut s = Rec::default();
        let b = Bandguards::new(&format!("{G} CONNECTED"), "up", 50.0, &mut s);
        (b, s)
    }

    fn cev(b: &mut Bandguards, s: &mut Rec, line: &str, at: f64) {
        b.circ_event(&evt(line, at), s);
    }

    #[test]
    fn a_failed_circuit_starts_the_clock_only_while_others_are_pending() {
        let (mut b, mut s) = connected();
        // Nothing else pending: no clock.
        cev(&mut b, &mut s, "650 CIRC 2 FAILED PURPOSE=GENERAL", 100.0);
        assert_eq!(b.no_circs_since, None);
        // The failing circuit itself does not count as pending.
        cev(&mut b, &mut s, "650 CIRC 1 LAUNCHED PURPOSE=GENERAL", 101.0);
        cev(&mut b, &mut s, "650 CIRC 1 FAILED PURPOSE=GENERAL", 102.0);
        assert_eq!(b.no_circs_since, None);
        // Only built circuits around: still none pending.
        cev(&mut b, &mut s, "650 CIRC 3 BUILT PURPOSE=GENERAL", 103.0);
        cev(&mut b, &mut s, "650 CIRC 4 FAILED PURPOSE=GENERAL", 104.0);
        assert_eq!(b.no_circs_since, None);
        // Other statuses never start it, even with a pending circuit.
        cev(&mut b, &mut s, "650 CIRC 5 LAUNCHED PURPOSE=GENERAL", 105.0);
        cev(&mut b, &mut s, "650 CIRC 6 CLOSED PURPOSE=GENERAL", 106.0);
        cev(&mut b, &mut s, "650 CIRC 7 LAUNCHED PURPOSE=GENERAL", 107.0);
        assert_eq!(b.no_circs_since, None);
        // A pending circuit and a FAILED one: the clock starts, and keeps its first value.
        cev(&mut b, &mut s, "650 CIRC 8 FAILED PURPOSE=GENERAL", 110.0);
        assert_eq!(b.no_circs_since, Some(110.0));
        cev(&mut b, &mut s, "650 CIRC 9 FAILED PURPOSE=GENERAL", 120.0);
        assert_eq!(b.no_circs_since, Some(110.0));
    }

    #[test]
    fn any_circuits_pending_table() {
        let (mut b, mut s) = connected();
        assert!(!b.any_circuits_pending(None));
        cev(&mut b, &mut s, "650 CIRC 1 BUILT PURPOSE=GENERAL", 1.0);
        assert!(!b.any_circuits_pending(None));
        assert!(!b.any_circuits_pending(Some("1")));
        cev(&mut b, &mut s, "650 CIRC 2 LAUNCHED PURPOSE=GENERAL", 2.0);
        assert!(b.any_circuits_pending(None));
        assert!(b.any_circuits_pending(Some("1")));
        assert!(!b.any_circuits_pending(Some("2")));
        cev(&mut b, &mut s, "650 CIRC 3 EXTENDED PURPOSE=GENERAL", 3.0);
        assert!(b.any_circuits_pending(Some("2")));
        cev(&mut b, &mut s, "650 CIRC 2 BUILT PURPOSE=GENERAL", 4.0);
        assert!(b.any_circuits_pending(None));
        cev(&mut b, &mut s, "650 CIRC 3 GUARD_WAIT PURPOSE=GENERAL", 5.0);
        assert!(!b.any_circuits_pending(None));
    }

    /// A pending circuit "1", a FAILED "2" at 100: the clock reads 100.
    fn failing() -> (Bandguards, Rec) {
        let (mut b, mut s) = connected();
        cev(&mut b, &mut s, "650 CIRC 1 LAUNCHED PURPOSE=GENERAL", 90.0);
        cev(&mut b, &mut s, "650 CIRC 2 FAILED PURPOSE=GENERAL", 100.0);
        assert_eq!(b.no_circs_since, Some(100.0));
        s.logs.clear();
        (b, s)
    }

    #[test]
    fn circuit_failure_timeline_without_a_network_outage() {
        let (mut b, mut s) = failing();
        let say = |n: u32| {
            vec![l(
                Level::Notice,
                &format!("Tor has been failing all circuits for {n} seconds!"),
            )]
        };
        assert!(beat(&mut b, &mut s, 129.0).is_empty());
        assert!(beat(&mut b, &mut s, 129.9).is_empty());
        assert_eq!(beat(&mut b, &mut s, 130.9), say(30));
        assert!(b.disconnected_circs);
        assert!(beat(&mut b, &mut s, 131.0).is_empty());
        assert!(beat(&mut b, &mut s, 159.0).is_empty());
        assert_eq!(beat(&mut b, &mut s, 160.0), say(60));
        assert!(beat(&mut b, &mut s, 161.0).is_empty());
    }

    #[test]
    fn circuit_failure_while_the_network_is_down_is_a_warning() {
        let (mut b, mut s) = failing();
        b.network_liveness_event(&evt("650 NETWORK_LIVENESS DOWN", 120.0), &mut s);
        s.logs.clear();
        assert!(beat(&mut b, &mut s, 129.0).is_empty());
        assert_eq!(
            beat(&mut b, &mut s, 130.9),
            vec![l(
                Level::Warn,
                "Tor has been disconnected for 10 seconds, and failing all circuits for 30 seconds!"
            )]
        );
        assert_eq!(
            beat(&mut b, &mut s, 160.0),
            vec![l(
                Level::Warn,
                "Tor has been disconnected for 40 seconds, and failing all circuits for 60 seconds!"
            )]
        );
        // UP again: back to the plain NOTICE.
        b.network_liveness_event(&evt("650 NETWORK_LIVENESS UP", 165.0), &mut s);
        assert_eq!(
            beat(&mut b, &mut s, 190.0),
            vec![l(
                Level::Notice,
                "Tor has been failing all circuits for 90 seconds!"
            )]
        );
    }

    #[test]
    fn network_liveness_events_set_and_clear_the_down_clock() {
        let (mut b, mut s) = connected();
        assert_eq!(b.network_down_since, None);
        let down = "650 NETWORK_LIVENESS DOWN";
        b.network_liveness_event(&evt(down, 120.5), &mut s);
        assert_eq!(b.network_down_since, Some(120.5));
        assert!(s.has(Level::Debug, down));
        b.network_liveness_event(&evt("650 NETWORK_LIVENESS SIDEWAYS", 130.0), &mut s);
        assert_eq!(b.network_down_since, Some(120.5));
        let up = "650 NETWORK_LIVENESS UP";
        b.network_liveness_event(&evt(up, 140.0), &mut s);
        assert_eq!(b.network_down_since, None);
        assert!(s.has(Level::Debug, up));
        b.network_liveness_event(&evt("650 NETWORK_LIVENESS UP", 141.0), &mut s);
        assert_eq!(b.network_down_since, None);
    }

    #[test]
    fn circuits_are_not_failing_when_none_is_pending_any_more() {
        let (mut b, mut s) = failing();
        // The pending circuit goes away without a resume.
        cev(&mut b, &mut s, "650 CIRC 1 CLOSED PURPOSE=GENERAL", 110.0);
        assert!(!b.any_circuits_pending(None));
        assert!(beat(&mut b, &mut s, 140.0).is_empty());
        assert!(!b.disconnected_circs);
    }

    #[test]
    fn connection_loss_takes_precedence_over_circuit_failure() {
        let (mut b, mut s) = failing();
        b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=0"), 105.0), &mut s);
        s.logs.clear();
        let got = beat(&mut b, &mut s, 140.0);
        assert_eq!(
            got,
            vec![l(
                Level::Warn,
                "We've been disconnected from the Tor network for 35 seconds!"
            )]
        );
        assert!(!b.disconnected_circs);
    }

    #[test]
    fn only_a_working_circuit_resumes_circuit_use() {
        let resumed = |n: u32| {
            vec![l(
                Level::Notice,
                &format!("Circuit use resumed after {n} seconds."),
            )]
        };
        let events = [
            "650 CIRC 3 EXTENDED PURPOSE=GENERAL",
            "650 CIRC 3 BUILT PURPOSE=GENERAL",
            "650 CIRC 3 GUARD_WAIT PURPOSE=GENERAL",
            "650 CIRC_BW ID=3 READ=0 WRITTEN=0 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0",
            // Resumes even for a circuit nobody has heard of.
            "650 CIRC_BW ID=999 READ=0 WRITTEN=0 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0",
        ];
        for line in events {
            let (mut b, mut s) = failing();
            cev(&mut b, &mut s, "650 CIRC 3 LAUNCHED PURPOSE=GENERAL", 101.0);
            beat(&mut b, &mut s, 130.0);
            assert!(b.disconnected_circs, "{line}");
            s.logs.clear();
            let ev = evt(line, 145.9);
            if ev.kind == "CIRC" {
                b.circ_event(&ev, &mut s);
            } else {
                b.circbw_event(&ev, &mut s);
            }
            assert_eq!(s.loud(), resumed(45), "{line}");
            assert_eq!(b.no_circs_since, None, "{line}");
            assert!(!b.disconnected_circs, "{line}");
            // Once is enough.
            s.logs.clear();
            b.circbw_event(&evt(events[3], 150.0), &mut s);
            assert!(s.loud().is_empty(), "{line}");
        }
        // Launching another circuit, or a FAILED/CLOSED one, does not.
        for line in [
            "650 CIRC 4 LAUNCHED PURPOSE=GENERAL",
            "650 CIRC 4 FAILED PURPOSE=GENERAL",
            "650 CIRC 1 CLOSED PURPOSE=GENERAL",
            "650 CIRC 4 SOMETHING PURPOSE=GENERAL",
        ] {
            let (mut b, mut s) = failing();
            beat(&mut b, &mut s, 130.0);
            assert!(b.disconnected_circs);
            s.logs.clear();
            b.circ_event(&evt(line, 145.0), &mut s);
            assert!(s.loud().is_empty(), "{line}");
            assert!(b.disconnected_circs, "{line}");
            assert_eq!(b.no_circs_since, Some(100.0), "{line}");
        }
    }

    // ── G3: a guard connection that dies takes its circuits with it ─────────

    const INTRO: &str = "PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED";

    /// Guards A (fake id 0) and B (fake id 1); in-use intro circuits "10" via A
    /// and "11" via B, a GENERAL circuit "12" via A and a second in-use one,
    /// "13", via A. Then A's connection closes (real id 99) at `base`.
    fn two_guards_one_dies(base: f64) -> (Bandguards, Rec) {
        let mut s = Rec::default();
        let both = format!("{G} CONNECTED\n{R} CONNECTED");
        let mut b = Bandguards::new(&both, "up", base - 50.0, &mut s);
        for line in [
            format!("650 CIRC 10 BUILT {G},{GC} {INTRO}"),
            format!("650 CIRC 11 BUILT {R},{GC} {INTRO}"),
            format!("650 CIRC 12 BUILT {G},{GC} PURPOSE=GENERAL"),
            format!("650 CIRC 13 BUILT {G},{GC} {INTRO}"),
        ] {
            cev(&mut b, &mut s, &line, base - 10.0);
        }
        s.logs.clear();
        b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=99"), base), &mut s);
        (b, s)
    }

    #[test]
    fn a_dying_guard_connection_marks_only_its_in_use_circuits() {
        within(|| {
            let (b, s) = two_guards_one_dies(100.0);
            assert_eq!(
                b.live_guard_conns,
                BTreeMap::from([("1".to_string(), fp('B'))])
            );
            for id in ["10", "13"] {
                assert_eq!(b.circs[id].possibly_destroyed_at, Some(100.0), "{id}");
                assert!(s.has(
                    Level::Info,
                    &format!("Marking possibly destroyed circ {id} at 100")
                ));
            }
            for id in ["11", "12"] {
                assert_eq!(b.circs[id].possibly_destroyed_at, None, "{id}");
            }
            assert_eq!(s.count_starting("Marking possibly destroyed"), 2);
            assert_eq!(b.guards[&fp('A')].killed_conn_at, 100.0);
            assert_eq!(b.guards[&fp('B')].killed_conn_at, 0.0);
        });
    }

    #[test]
    fn a_guard_with_no_in_use_circuit_is_not_marked_as_having_killed_anything() {
        within(|| {
            let mut s = Rec::default();
            let mut b = Bandguards::new(&format!("{G} CONNECTED"), "up", 50.0, &mut s);
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC 12 BUILT {G},{GC} PURPOSE=GENERAL"),
                60.0,
            );
            b.orconn_event(&evt(&format!("650 ORCONN {G} CLOSED ID=0"), 100.0), &mut s);
            assert_eq!(b.guards[&fp('A')].killed_conn_at, 0.0);
            assert_eq!(s.count_starting("Marking possibly destroyed"), 0);
        });
    }

    fn close_circuit_event(id: &str, extra: &str) -> String {
        format!("650 CIRC {id} CLOSED {G},{GC} PURPOSE=HS_SERVICE_INTRO {extra}")
    }

    #[test]
    fn a_circuit_closed_by_the_channel_inside_the_window_is_reported() {
        // The same decision at a large and a small clock: the lag is a
        // difference, not a ratio.
        for (base, at) in [(100.0, 102.0), (1.0, 3.0), (100.0, 100.0)] {
            within(move || {
                let (mut b, mut s) = two_guards_one_dies(base);
                s.logs.clear();
                let raw =
                    close_circuit_event("10", "REASON=DESTROYED REMOTE_REASON=CHANNEL_CLOSED");
                cev(&mut b, &mut s, &raw, at);
                let a = fp('A');
                assert_eq!(
                    s.loud(),
                    vec![l(
                        Level::Notice,
                        &format!("The connection to guard {a} was closed with a live circuit.")
                    )],
                    "{base} {at}"
                );
                assert!(s.has(
                    Level::Info,
                    &format!("The connection to guard {a} was closed with circuit 10 on it.")
                ));
                assert!(s.has(Level::Debug, &format!("Closed hs circ for {raw}")));
                assert_eq!(s.count_starting("Circuit 10 possibly destroyed"), 0);
                assert_eq!(b.guards[&a].killed_conn_at, 0.0);
                assert!(!b.circs.contains_key("10"));
                assert_eq!(b.circ_order, vec!["11", "12", "13"]);
            });
        }
    }

    #[test]
    fn the_second_circuit_of_a_dead_connection_is_only_logged_at_info() {
        within(|| {
            let (mut b, mut s) = two_guards_one_dies(100.0);
            s.logs.clear();
            let chan = "REMOTE_REASON=CHANNEL_CLOSED";
            cev(&mut b, &mut s, &close_circuit_event("10", chan), 101.0);
            assert_eq!(s.loud().len(), 1);
            s.logs.clear();
            cev(&mut b, &mut s, &close_circuit_event("13", chan), 101.0);
            assert!(s.loud().is_empty());
            let a = fp('A');
            assert!(s.has(
                Level::Info,
                &format!("The connection to guard {a} was closed with circuit 13 on it.")
            ));
        });
    }

    #[test]
    fn a_circuit_closed_outside_the_window_or_for_another_reason_is_not_blamed() {
        for (at, extra, shown) in [
            (102.5, "REMOTE_REASON=CHANNEL_CLOSED", "(102 - 100)"),
            (101.0, "REMOTE_REASON=FINISHED", "(101 - 100)"),
            // REASON= is the local reason; only REMOTE_REASON counts.
            (101.0, "REASON=CHANNEL_CLOSED", "(101 - 100)"),
            (101.0, "", "(101 - 100)"),
        ] {
            within(move || {
                let (mut b, mut s) = two_guards_one_dies(100.0);
                s.logs.clear();
                cev(&mut b, &mut s, &close_circuit_event("10", extra), at);
                assert!(s.loud().is_empty(), "{at} {extra}");
                assert!(
                    s.has(
                        Level::Info,
                        &format!(
                            "Circuit 10 possibly destroyed, but outside of the time window {shown}"
                        )
                    ),
                    "{at} {extra}: {:?}",
                    s.logs
                );
                assert_eq!(s.count_starting("The connection to guard"), 0);
                assert_eq!(b.guards[&fp('A')].killed_conn_at, 100.0);
                assert!(!b.circs.contains_key("10"));
            });
        }
    }

    #[test]
    fn closing_a_circuit_that_was_never_marked_says_nothing_about_the_guard() {
        within(|| {
            let (mut b, mut s) = two_guards_one_dies(100.0);
            s.logs.clear();
            // 11 is in use but its guard is alive; 12 is not in use.
            for id in ["11", "12"] {
                cev(
                    &mut b,
                    &mut s,
                    &close_circuit_event(id, "REMOTE_REASON=CHANNEL_CLOSED"),
                    101.0,
                );
                assert_eq!(s.count_starting("The connection to guard"), 0, "{id}");
                assert_eq!(s.count_starting("Circuit"), 0, "{id}");
                assert!(s.has(
                    Level::Debug,
                    &format!(
                        "Closed hs circ for {}",
                        close_circuit_event(id, "REMOTE_REASON=CHANNEL_CLOSED")
                    )
                ));
            }
            assert_eq!(b.circ_order, vec!["10", "13"]);
            // A circuit we never saw: no log at all.
            s.logs.clear();
            cev(&mut b, &mut s, &close_circuit_event("77", ""), 101.0);
            assert!(s.logs.is_empty());
        });
    }

    // ── G4: dropped cells ───────────────────────────────────────────────────

    fn cs(
        purpose: &str,
        hs: Option<&str>,
        built: bool,
        read: f64,
        delivered: f64,
        allowed: f64,
    ) -> CircStat {
        CircStat {
            circ_id: "7".into(),
            purpose: Some(purpose.into()),
            hs_state: hs.map(String::from),
            built,
            read_bytes: read,
            delivered_read_bytes: delivered,
            dropped_cells_allowed: allowed,
            ..CircStat::default()
        }
    }

    #[test]
    fn dropped_read_cells_are_read_cells_minus_accounted_cells() {
        let dropped = |read: f64, delivered: f64, overhead: f64| {
            CircStat {
                read_bytes: read,
                delivered_read_bytes: delivered,
                overhead_read_bytes: overhead,
                ..CircStat::default()
            }
            .dropped_read_cells()
        };
        assert_eq!(dropped(1018.0, 498.0, 0.0), 1.0);
        assert_eq!(dropped(509.0, 249.0, 0.0), 0.5);
        // Overhead counts the same as delivered data.
        assert_eq!(dropped(509.0, 0.0, 249.0), 0.5);
        assert_eq!(dropped(1018.0, 249.0, 249.0), 1.0);
        assert_eq!(dropped(0.0, 0.0, 0.0), 0.0);
        let c = CircStat {
            read_bytes: 1018.0,
            sent_bytes: 5.0,
            ..CircStat::default()
        };
        assert_eq!(c.total_bytes(), 1023.0);
    }

    #[test]
    fn the_cell_constants_are_tors() {
        assert_eq!(CELL_PAYLOAD_SIZE, 509.0);
        assert_eq!(RELAY_PAYLOAD_SIZE, 498.0);
        assert_eq!(CELL_DATA_RATE, 498.0 / 509.0);
        assert_eq!(509.0 * CELL_DATA_RATE, 498.0);
    }

    #[test]
    fn states_prints_the_current_and_the_old_state() {
        let mut c = CircStat::default();
        assert_eq!(c.states(), "(in state None None; old state None None)");
        c.purpose = Some("P".into());
        c.hs_state = Some("S".into());
        assert_eq!(c.states(), "(in state P S; old state None None)");
        c.old_purpose = Some("OP".into());
        c.old_hs_state = Some("OS".into());
        assert_eq!(c.states(), "(in state P S; old state OP OS)");
    }

    #[test]
    fn drop_allowance_by_purpose_and_state() {
        // (purpose, hs_state, allowance afterwards); the start value 7 shows
        // a purpose that sets nothing.
        for (purpose, hs, want) in [
            ("HS_SERVICE_REND", Some("HSSR_CONNECTING"), 1.0),
            ("HS_SERVICE_REND", Some("HSSR_JOINED"), 0.0),
            ("HS_SERVICE_REND", None, 0.0),
            ("HS_CLIENT_REND", Some("HSCR_CONNECTING"), 1.0),
            ("HS_CLIENT_REND", None, 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_DONE"), 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_CONNECTING"), 0.0),
            ("HS_CLIENT_INTRO", None, 0.0),
            ("HS_SERVICE_INTRO", Some("HSSI_ESTABLISHED"), 7.0),
            ("GENERAL", None, 7.0),
            ("", None, 7.0),
        ] {
            let mut c = CircStat {
                dropped_cells_allowed: 7.0,
                ..CircStat::default()
            };
            Bandguards::set_drop_allowance_for_purpose(&mut c, purpose, hs);
            assert_eq!(c.dropped_cells_allowed, want, "{purpose} {hs:?}");
        }
    }

    #[test]
    fn every_circ_event_resets_the_allowance_for_its_state() {
        let (mut b, mut s) = connected();
        cev(
            &mut b,
            &mut s,
            &format!(
                "650 CIRC 6 EXTENDED {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"
            ),
            1.0,
        );
        assert_eq!(b.circs["6"].dropped_cells_allowed, 1.0);
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 6 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_JOINED"),
            2.0,
        );
        assert_eq!(b.circs["6"].dropped_cells_allowed, 0.0);
        assert_eq!(b.circs["6"].purpose.as_deref(), Some("HS_SERVICE_REND"));
        assert_eq!(b.circs["6"].hs_state.as_deref(), Some("HSSR_JOINED"));
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 8 BUILT {G},{R} PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED"),
            3.0,
        );
        assert_eq!(b.circs["8"].dropped_cells_allowed, 1.0);
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 9 BUILT {G},{R} PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE"),
            4.0,
        );
        assert_eq!(b.circs["9"].dropped_cells_allowed, 1.0);
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 9 BUILT {G},{R} PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING"),
            5.0,
        );
        assert_eq!(b.circs["9"].dropped_cells_allowed, 0.0);
    }

    fn limits(c: &CircStat) -> (Vec<(u8, String)>, Vec<String>) {
        let mut s = Rec::default();
        Bandguards::check_circuit_limits(c, &mut s);
        (s.logs, s.closes)
    }

    #[test]
    fn dropped_cell_decisions_by_circuit_state() {
        let st = |p: &str, h: &str| format!("(in state {p} {h}; old state None None)");
        let none: &str = "None";
        let est = "HSSI_ESTABLISHED";
        // Over the allowance: (circuit, expected log, closed?)
        let over: Vec<(CircStat, (Level, String), bool)> = vec![
            (
                cs("HS_SERVICE_INTRO", Some(est), true, 1018.0, 0.0, 0.0),
                (Level::Notice, format!("Tor bug #29699: Got 2 dropped cell on circ 7 {}.", st("HS_SERVICE_INTRO", est))),
                true,
            ),
            // Not built yet but an established intro: the same rule applies first.
            (
                cs("HS_SERVICE_INTRO", Some(est), false, 1018.0, 0.0, 0.0),
                (Level::Notice, format!("Tor bug #29699: Got 2 dropped cell on circ 7 {}.", st("HS_SERVICE_INTRO", est))),
                true,
            ),
            (
                cs("HS_SERVICE_INTRO", Some("HSSI_CONNECTING"), true, 1018.0, 0.0, 0.0),
                (Level::Warn, format!("Possible Tor bug, or possible attack if very frequent: Got 2 dropped cell on circ 7 {}", st("HS_SERVICE_INTRO", "HSSI_CONNECTING"))),
                true,
            ),
            (
                cs("GENERAL", Some(est), true, 1018.0, 0.0, 0.0),
                (Level::Warn, format!("Possible Tor bug, or possible attack if very frequent: Got 2 dropped cell on circ 7 {}", st("GENERAL", est))),
                true,
            ),
            (
                cs("HS_SERVICE_INTRO", None, true, 1018.0, 0.0, 0.0),
                (Level::Warn, format!("Possible Tor bug, or possible attack if very frequent: Got 2 dropped cell on circ 7 {}", st("HS_SERVICE_INTRO", none))),
                true,
            ),
            // 1.5 dropped cells print as 1.
            (
                cs("GENERAL", None, true, 764.0, 0.0, 0.0),
                (Level::Warn, format!("Possible Tor bug, or possible attack if very frequent: Got 1 dropped cell on circ 7 {}", st("GENERAL", none))),
                true,
            ),
            (
                cs("GENERAL", None, false, 1018.0, 0.0, 0.0),
                (Level::Info, format!("Tor bug #29927: Got a dropped cell on circ 7 {}.", st("GENERAL", none))),
                false,
            ),
            // One cell over an allowance of one.
            (
                cs("HS_CLIENT_REND", None, true, 1018.0, 0.0, 1.0),
                (Level::Warn, format!("Possible Tor bug, or possible attack if very frequent: Got 2 dropped cell on circ 7 {}", st("HS_CLIENT_REND", none))),
                true,
            ),
        ];
        for (c, (lv, msg), closed) in over {
            let (logs, closes) = limits(&c);
            assert_eq!(logs, vec![l(lv, &msg)], "{c:?}");
            assert_eq!(
                closes,
                if closed {
                    vec!["7"]
                } else {
                    Vec::<&str>::new()
                },
                "{c:?}"
            );
        }
        // At or under the allowance: logged for the record, never closed.
        let under: Vec<(CircStat, &str)> = vec![
            (
                cs("PATH_BIAS_TESTING", None, true, 509.0, 0.0, 1.0),
                "29786",
            ),
            (
                cs(
                    "PATH_BIAS_TESTING",
                    Some("HSSR_CONNECTING"),
                    true,
                    509.0,
                    0.0,
                    1.0,
                ),
                "29786",
            ),
            (
                cs(
                    "HS_SERVICE_REND",
                    Some("HSSR_CONNECTING"),
                    true,
                    509.0,
                    0.0,
                    1.0,
                ),
                "29700",
            ),
            (
                cs(
                    "HS_SERVICE_REND",
                    Some("HSSR_JOINED"),
                    true,
                    509.0,
                    0.0,
                    1.0,
                ),
                "29927",
            ),
            (cs("HS_SERVICE_REND", None, true, 509.0, 0.0, 1.0), "29927"),
            (
                cs("GENERAL", Some("HSSR_CONNECTING"), true, 509.0, 0.0, 1.0),
                "29927",
            ),
            (cs("HS_CLIENT_REND", None, true, 509.0, 0.0, 1.0), "29927"),
            // Half a cell is still a dropped cell, below any allowance.
            (cs("GENERAL", None, true, 509.0, 249.0, 1.0), "29927"),
        ];
        for (c, bug) in under {
            let (logs, closes) = limits(&c);
            let p = c.purpose.clone().unwrap();
            let h = c.hs_state.clone().unwrap_or_else(|| "None".into());
            assert_eq!(
                logs,
                vec![l(
                    Level::Info,
                    &format!(
                        "Tor bug #{bug}: Got a dropped cell on circ 7 {}.",
                        st(&p, &h)
                    )
                )],
                "{c:?}"
            );
            assert!(closes.is_empty(), "{c:?}");
        }
        // No dropped cell, or fewer cells than were accounted for: silent.
        for c in [
            cs("GENERAL", None, true, 509.0, 498.0, 0.0),
            cs("GENERAL", None, true, 0.0, 0.0, 0.0),
            cs("GENERAL", None, true, 0.0, 498.0, 0.0),
            cs("HS_SERVICE_INTRO", Some(est), true, 509.0, 498.0, 0.0),
            cs("HS_CLIENT_REND", None, true, 0.0, 996.0, 1.0),
        ] {
            let (logs, closes) = limits(&c);
            assert!(logs.is_empty() && closes.is_empty(), "{c:?}: {logs:?}");
        }
    }

    #[test]
    fn hsdir_circuits_are_closed_past_thirty_kilobytes() {
        let hs = |sent: f64, read: f64, delivered: f64, is_hsdir: bool| CircStat {
            is_hsdir,
            sent_bytes: sent,
            ..cs("HS_CLIENT_HSDIR", None, true, read, delivered, 0.0)
        };
        let over = |total: &str| {
            vec![l(
                Level::Warn,
                &format!("Circ 7 exceeded CIRC_MAX_HSDESC_KILOBYTES: {total} > 30720. "),
            )]
        };
        let (logs, closes) = limits(&hs(30720.0, 0.0, 0.0, true));
        assert!(logs.is_empty() && closes.is_empty());
        let (logs, closes) = limits(&hs(30721.0, 0.0, 0.0, true));
        assert_eq!((logs, closes), (over("30721"), vec!["7".to_string()]));
        // Read and sent bytes add up (15270 bytes is 30 cells, all accounted for).
        let (logs, closes) = limits(&hs(15451.0, 15270.0, 14940.0, true));
        assert_eq!((logs, closes), (over("30721"), vec!["7".to_string()]));
        let (logs, closes) = limits(&hs(15450.0, 15270.0, 14940.0, true));
        assert!(logs.is_empty() && closes.is_empty());
        // Only descriptor-fetch circuits have the limit.
        let (logs, closes) = limits(&hs(100e6, 0.0, 0.0, false));
        assert!(logs.is_empty() && closes.is_empty());
    }

    #[test]
    fn hsdir_purposes_flag_the_circuit_at_creation_and_on_purpose_change() {
        let (mut b, mut s) = connected();
        for (id, purpose, want) in [
            ("1", "HS_CLIENT_HSDIR", true),
            ("2", "HS_SERVICE_HSDIR", true),
            ("3", "HS_CLIENT_REND", false),
            ("4", "GENERAL", false),
        ] {
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC {id} EXTENDED {G},{R} PURPOSE={purpose}"),
                1.0,
            );
            assert_eq!(b.circs[id].is_hsdir, want, "{purpose}");
        }
        // A cannibalised circuit becomes an hsdir circuit later.
        for (purpose, want) in [
            ("HS_CLIENT_HSDIR", true),
            ("HS_SERVICE_HSDIR", true),
            ("HS_CLIENT_REND", false),
        ] {
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=GENERAL"),
                1.0,
            );
            b.circs.get_mut("5").unwrap().is_hsdir = false;
            b.circ_minor_event(
                &evt(&format!("650 CIRC_MINOR 5 CANNIBALIZED {G},{R} PURPOSE={purpose} OLD_PURPOSE=GENERAL"), 2.0),
                &mut s,
            );
            assert_eq!(b.circs["5"].is_hsdir, want, "{purpose}");
        }
        // And is then held to the 30 KB limit.
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 6 BUILT {G},{R} PURPOSE=GENERAL"),
            1.0,
        );
        b.circ_minor_event(
            &evt(&format!("650 CIRC_MINOR 6 CANNIBALIZED {G},{R} PURPOSE=HS_CLIENT_HSDIR OLD_PURPOSE=GENERAL"), 2.0),
            &mut s,
        );
        s.closes.clear();
        b.circbw_event(&evt("650 CIRC_BW ID=6 READ=0 WRITTEN=30720 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0", 3.0), &mut s);
        assert!(s.closes.is_empty());
        b.circbw_event(&evt("650 CIRC_BW ID=6 READ=0 WRITTEN=1 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0", 4.0), &mut s);
        assert_eq!(s.closes, vec!["6"]);
        // A big transfer on any other circuit is none of our business.
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 7 BUILT {G},{R} PURPOSE=GENERAL"),
            1.0,
        );
        s.closes.clear();
        b.circbw_event(&evt("650 CIRC_BW ID=7 READ=0 WRITTEN=100000000 DELIVERED_READ=0 OVERHEAD_READ=0 DELIVERED_WRITTEN=0 OVERHEAD_WRITTEN=0", 3.0), &mut s);
        assert!(s.closes.is_empty());
    }

    fn bw_line(id: &str, r: u32, w: u32, dr: u32, or: u32, dw: u32, ow: u32) -> String {
        format!("650 CIRC_BW ID={id} READ={r} WRITTEN={w} TIME=x DELIVERED_READ={dr} OVERHEAD_READ={or} DELIVERED_WRITTEN={dw} OVERHEAD_WRITTEN={ow}")
    }

    #[test]
    fn data_beyond_the_cell_payload_is_an_error() {
        // (read, written, dr, or, dw, ow, read error, write error)
        let rows = [
            (509, 0, 498, 0, 0, 0, false, false),
            (509, 0, 499, 0, 0, 0, true, false),
            (509, 0, 300, 198, 0, 0, false, false),
            (509, 0, 300, 199, 0, 0, true, false),
            (509, 0, 498, 1, 0, 0, true, false),
            (509, 0, 0, 499, 0, 0, true, false),
            (0, 509, 0, 0, 498, 0, false, false),
            (0, 509, 0, 0, 499, 0, false, true),
            (0, 509, 0, 0, 300, 198, false, false),
            (0, 509, 0, 0, 300, 199, false, true),
            (0, 509, 0, 0, 0, 499, false, true),
            (509, 509, 499, 0, 499, 0, true, true),
        ];
        for (r, w, dr, or, dw, ow, rerr, werr) in rows {
            let (mut b, mut s) = connected();
            cev(&mut b, &mut s, "650 CIRC 5 BUILT PURPOSE=GENERAL", 1.0);
            s.logs.clear();
            let raw = bw_line("5", r, w, dr, or, dw, ow);
            b.circbw_event(&evt(&raw, 2.0), &mut s);
            let mut want = vec![l(Level::Debug, &raw)];
            if rerr {
                want.push(l(
                    Level::Error,
                    &format!("Application read data exceeds cell data:{raw}"),
                ));
            }
            if werr {
                want.push(l(
                    Level::Error,
                    &format!("Application written data exceeds cell data:{raw}"),
                ));
            }
            assert_eq!(s.logs, want, "{raw}");
        }
    }

    #[test]
    fn circuit_bandwidth_accumulates_per_circuit() {
        let (mut b, mut s) = connected();
        cev(&mut b, &mut s, "650 CIRC 5 BUILT PURPOSE=GENERAL", 1.0);
        cev(&mut b, &mut s, "650 CIRC 6 BUILT PURPOSE=GENERAL", 1.0);
        b.circbw_event(&evt(&bw_line("5", 100, 7, 10, 1, 0, 0), 2.0), &mut s);
        b.circbw_event(&evt(&bw_line("5", 50, 8, 20, 2, 0, 0), 3.0), &mut s);
        b.circbw_event(&evt(&bw_line("6", 9, 9, 1, 1, 0, 0), 3.0), &mut s);
        let c = &b.circs["5"];
        assert_eq!(
            (
                c.read_bytes,
                c.sent_bytes,
                c.delivered_read_bytes,
                c.overhead_read_bytes
            ),
            (150.0, 15.0, 30.0, 3.0)
        );
        let c = &b.circs["6"];
        assert_eq!((c.read_bytes, c.sent_bytes), (9.0, 9.0));
        // A circuit we do not track leaves no trace and no log.
        s.logs.clear();
        b.circbw_event(&evt(&bw_line("99", 1000, 1000, 0, 0, 0, 0), 4.0), &mut s);
        assert!(s.logs.is_empty());
        assert!(!b.circs.contains_key("99"));
    }

    // ── circ_event / circ_minor_event bookkeeping ───────────────────────────

    #[test]
    fn circ_event_tracks_new_circuits_and_marks_hs_circuits_in_use() {
        let (mut b, mut s) = connected();
        let line =
            format!("650 CIRC 5 EXTENDED {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_JOINED");
        cev(&mut b, &mut s, &line, 1.0);
        assert!(s.has(Level::Debug, &format!("Added circ for {line}")));
        assert_eq!(b.circ_order, vec!["5"]);
        assert!(!b.circs["5"].built && !b.circs["5"].in_use);
        assert!(b.circs["5"].created_at > 1.7e9);
        // Delivered bytes show in the in-use message.
        b.circbw_event(&evt(&bw_line("5", 1018, 0, 996, 0, 0, 0), 2.0), &mut s);
        s.logs.clear();
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_JOINED"),
            3.0,
        );
        assert_eq!(s.count_starting("Added circ"), 0);
        assert!(s.has(Level::Debug, "Circ 5 now in-use. 996 delivered bytes."));
        assert!(b.circs["5"].built && b.circs["5"].in_use);
        assert_eq!(b.circs["5"].guard_fp, Some(fp('A')));
        assert_eq!(b.circ_order, vec!["5"]);
        // Both HS_CLIENT_* and HS_SERVICE_* purposes count; GUARD_WAIT is a build too.
        for (id, purpose, status, in_use) in [
            ("6", "HS_CLIENT_REND", "BUILT", true),
            ("7", "HS_SERVICE_INTRO", "GUARD_WAIT", true),
            ("8", "HS_CLIENT_HSDIR", "BUILT", true),
            ("9", "GENERAL", "BUILT", false),
            ("10", "HS_VANGUARDS", "BUILT", false),
            ("11", "HS_SERVICE_INTRO", "EXTENDED", false),
        ] {
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC {id} {status} {G},{R} PURPOSE={purpose}"),
                3.0,
            );
            assert_eq!(b.circs[id].in_use, in_use, "{purpose} {status}");
            assert_eq!(b.circs[id].guard_fp.is_some(), in_use, "{purpose} {status}");
            assert_eq!(
                b.circs[id].built,
                status != "EXTENDED",
                "{purpose} {status}"
            );
        }
    }

    #[test]
    fn circ_minor_event_records_the_old_state_and_marks_vanguard_circuits_in_use() {
        let (mut b, mut s) = connected();
        // An unknown circuit is ignored without a word.
        s.logs.clear();
        b.circ_minor_event(
            &evt(
                &format!("650 CIRC_MINOR 5 PURPOSE_CHANGED {G},{R} PURPOSE=GENERAL"),
                1.0,
            ),
            &mut s,
        );
        assert!(s.logs.is_empty());
        assert!(b.circs.is_empty());
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=HS_VANGUARDS"),
            1.0,
        );
        assert!(!b.circs["5"].in_use);
        let line = format!(
            "650 CIRC_MINOR 5 PURPOSE_CHANGED {G},{GC} PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED OLD_PURPOSE=HS_VANGUARDS OLD_HS_STATE=HSVI_X"
        );
        s.logs.clear();
        b.circ_minor_event(&evt(&line, 2.0), &mut s);
        let c = &b.circs["5"];
        assert!(c.in_use);
        assert_eq!(c.guard_fp, Some(fp('A')));
        assert_eq!(
            c.states(),
            "(in state HS_SERVICE_INTRO HSSI_ESTABLISHED; old state HS_VANGUARDS HSVI_X)"
        );
        assert!(s.has(Level::Debug, "Circ 5 now in-use. 0 delivered bytes."));
        assert!(s.has(Level::Debug, &line));
        // Any other status leaves in_use alone, whatever the old purpose was.
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 6 BUILT {G},{R} PURPOSE=HS_VANGUARDS"),
            1.0,
        );
        b.circ_minor_event(
            &evt(&format!("650 CIRC_MINOR 6 CANNIBALIZED {G},{R} PURPOSE=HS_CLIENT_REND OLD_PURPOSE=HS_VANGUARDS"), 2.0),
            &mut s,
        );
        assert!(!b.circs["6"].in_use);
        assert_eq!(b.circs["6"].guard_fp, None);
        // PURPOSE_CHANGED from anything else is not "in use" either.
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 7 BUILT {G},{R} PURPOSE=GENERAL"),
            1.0,
        );
        b.circ_minor_event(
            &evt(&format!("650 CIRC_MINOR 7 PURPOSE_CHANGED {G},{R} PURPOSE=HS_CLIENT_REND OLD_PURPOSE=GENERAL"), 2.0),
            &mut s,
        );
        assert!(!b.circs["7"].in_use);
    }

    #[test]
    fn path_bias_testing_allows_the_known_pending_cell() {
        // (old purpose, old hs state, allowance afterwards); the circuit starts at 0.
        let rows: [(&str, Option<&str>, f64); 11] = [
            ("HS_SERVICE_INTRO", Some("HSSI_CONNECTING"), 1.0),
            ("HS_CLIENT_REND", Some("HSCR_CONNECTING"), 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_CONNECTING"), 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_INTRO_SENT"), 1.0),
            ("HS_CLIENT_INTRO", None, 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_DONE"), 0.0),
            ("HS_SERVICE_INTRO", Some("HSSI_ESTABLISHED"), 0.0),
            ("HS_CLIENT_REND", Some("HSCR_ESTABLISHED_IDLE"), 0.0),
            // Right state, wrong purpose, and the reverse.
            ("HS_CLIENT_REND", Some("HSSI_CONNECTING"), 0.0),
            ("HS_SERVICE_INTRO", Some("HSCR_CONNECTING"), 0.0),
            ("GENERAL", Some("HSSI_CONNECTING"), 0.0),
        ];
        for (op, os, want) in rows {
            let (mut b, mut s) = connected();
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC 5 BUILT {G},{R} PURPOSE={op}"),
                1.0,
            );
            b.circs.get_mut("5").unwrap().dropped_cells_allowed = 0.0;
            let old_state = os.map(|o| format!(" OLD_HS_STATE={o}")).unwrap_or_default();
            b.circ_minor_event(
                &evt(&format!("650 CIRC_MINOR 5 PURPOSE_CHANGED {G},{R} PURPOSE=PATH_BIAS_TESTING OLD_PURPOSE={op}{old_state}"), 2.0),
                &mut s,
            );
            assert_eq!(b.circs["5"].dropped_cells_allowed, want, "{op} {os:?}");
        }
        // Without PURPOSE_CHANGED nothing is allowed.
        let (mut b, mut s) = connected();
        cev(
            &mut b,
            &mut s,
            &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=HS_CLIENT_REND"),
            1.0,
        );
        b.circs.get_mut("5").unwrap().dropped_cells_allowed = 0.0;
        b.circ_minor_event(
            &evt(&format!("650 CIRC_MINOR 5 CANNIBALIZED {G},{R} PURPOSE=PATH_BIAS_TESTING OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_CONNECTING"), 2.0),
            &mut s,
        );
        assert_eq!(b.circs["5"].dropped_cells_allowed, 0.0);
    }

    #[test]
    fn a_purpose_change_resets_the_allowance_for_the_new_purpose() {
        let rows: [(&str, Option<&str>, f64); 6] = [
            ("HS_SERVICE_REND", Some("HSSR_CONNECTING"), 1.0),
            ("HS_SERVICE_REND", Some("HSSR_JOINED"), 0.0),
            ("HS_CLIENT_REND", Some("HSCR_JOINED"), 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_DONE"), 1.0),
            ("HS_CLIENT_INTRO", Some("HSCI_CONNECTING"), 0.0),
            ("GENERAL", None, 7.0),
        ];
        for (purpose, hs, want) in rows {
            let (mut b, mut s) = connected();
            cev(
                &mut b,
                &mut s,
                &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=GENERAL"),
                1.0,
            );
            b.circs.get_mut("5").unwrap().dropped_cells_allowed = 7.0;
            let state = hs.map(|h| format!(" HS_STATE={h}")).unwrap_or_default();
            b.circ_minor_event(
                &evt(&format!("650 CIRC_MINOR 5 PURPOSE_CHANGED {G},{R} PURPOSE={purpose}{state} OLD_PURPOSE=GENERAL"), 2.0),
                &mut s,
            );
            assert_eq!(b.circs["5"].dropped_cells_allowed, want, "{purpose} {hs:?}");
            assert_eq!(b.circs["5"].purpose.as_deref(), Some(purpose));
        }
    }

    // ── G5: circuit age ─────────────────────────────────────────────────────

    #[test]
    fn circuits_are_closed_strictly_after_a_day() {
        let (mut b, mut s) = connected();
        cev(&mut b, &mut s, "650 CIRC 9 BUILT PURPOSE=GENERAL", 1.0);
        cev(&mut b, &mut s, "650 CIRC 10 BUILT PURPOSE=GENERAL", 1.0);
        b.set_created_at("9", 1000.0);
        b.set_created_at("10", 1000.0 + 80000.0);
        cev(&mut b, &mut s, "650 CIRC 11 BUILT PURPOSE=GENERAL", 1.0);
        b.set_created_at("11", 1000.0);
        s.logs.clear();
        b.check_circ_ages(1000.0 + 86400.0, &mut s);
        assert!(s.closes.is_empty() && s.logs.is_empty());
        // A short age must not count (a 24 h limit is not 24 + 3600 s).
        b.check_circ_ages(1000.0 + 4000.0, &mut s);
        assert!(s.closes.is_empty() && s.logs.is_empty());
        // Circuit 10 is only 5400 s old here and stays.
        b.check_circ_ages(1000.0 + 86400.5, &mut s);
        assert_eq!(s.closes, vec!["9", "11"]);
        let late = "CIRC_MAX_AGE_HOURS: 24.000138888888888 > 24. ";
        assert_eq!(
            s.logs,
            vec![
                l(Level::Notice, &format!("Circ 9 exceeded {late}")),
                l(Level::Notice, &format!("Circ 11 exceeded {late}")),
            ]
        );
        s.logs.clear();
        s.closes.clear();
        // 90000 s is exactly 25 h.
        b.check_circ_ages(1000.0 + 90000.0, &mut s);
        assert_eq!(s.closes, vec!["9", "11"]);
        assert_eq!(
            s.logs[0],
            l(
                Level::Notice,
                "Circ 9 exceeded CIRC_MAX_AGE_HOURS: 25.0 > 24. "
            )
        );
    }

    #[test]
    fn the_heartbeat_checks_ages_against_the_wall_clock() {
        let (mut b, mut s) = connected();
        cev(&mut b, &mut s, "650 CIRC 9 BUILT PURPOSE=GENERAL", 1.0);
        cev(&mut b, &mut s, "650 CIRC 10 BUILT PURPOSE=GENERAL", 1.0);
        b.set_created_at("9", now() - 90000.0);
        b.bw_event(&evt("650 BW 0 0", now()), &mut s);
        assert_eq!(s.closes, vec!["9"]);
        assert_eq!(
            s.count_starting("Circ 9 exceeded CIRC_MAX_AGE_HOURS: 25.0"),
            1
        );
    }

    // ── G7: rendguard ───────────────────────────────────────────────────────

    fn rend(used: f64, weight: f64, total: f64) -> Rendguard {
        Rendguard {
            use_counts: BTreeMap::from([("R".to_string(), UseCount { used, weight })]),
            total_use_counts: total,
        }
    }

    #[test]
    fn a_relay_at_exactly_five_times_its_weight_is_allowed() {
        let mut s = Rec::default();
        // 500 of 1000 uses against a weight of 0.1: a use rate of exactly 5x.
        let mut rg = rend(499.0, 0.1, 999.0);
        assert!(rg.valid_rend_use("R", &mut s));
        assert_eq!(
            s.logs,
            vec![l(
                Level::Debug,
                "Relay R used 500 times out of 1000, for a use rate of 50.000000%. It has a consensus weight of 10.000000%"
            )]
        );
        assert_eq!(
            (rg.use_counts["R"].used, rg.total_use_counts),
            (500.0, 1000.0)
        );
    }

    #[test]
    fn a_relay_over_five_times_its_weight_is_refused_with_a_notice() {
        let mut s = Rec::default();
        let mut rg = rend(500.0, 0.1, 999.0);
        assert!(!rg.valid_rend_use("R", &mut s));
        assert_eq!(
            s.logs,
            vec![
                l(Level::Debug, "Relay R used 501 times out of 1000, for a use rate of 50.100000%. It has a consensus weight of 10.000000%"),
                l(Level::Notice, "Relay R used 501 times out of 1000, for a use rate of 50.100000%. This is above its consensus weight of 10.000000%"),
            ]
        );
    }

    #[test]
    fn rendguard_waits_for_enough_data_before_judging() {
        // (uses of the relay before, all uses before, weight, allowed)
        for (used, total, w, ok) in [
            (99.0, 999.0, 0.01, false), // 100 of 1000: both minimums met, 10% > 5 x 1%
            (98.0, 999.0, 0.01, true),  // only 99 uses of that relay
            (99.0, 998.0, 0.01, true),  // 999 uses in all
            (98.0, 998.0, 0.01, true),  // neither
            (100.0, 1500.0, 0.01, false), // 101 of 1501
            (99.0, 999.0, 0.5, true),   // 10% is nothing against a 50% weight
        ] {
            let mut s = Rec::default();
            let mut rg = rend(used, w, total);
            assert_eq!(rg.valid_rend_use("R", &mut s), ok, "{used} {total} {w}");
        }
    }

    #[test]
    fn a_relay_outside_the_consensus_is_counted_under_one_shared_name() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        rg.xfer_use_counts(&[], &BTreeMap::new(), &mut s);
        s.logs.clear();
        assert!(rg.valid_rend_use("XYZ", &mut s));
        assert_eq!(
            s.logs,
            vec![
                l(Level::Info, "Relay XYZ is not in our consensus."),
                l(Level::Debug, "Relay XYZ (not in-consensus) used 1 times out of 1, for a use rate of 100.000000%. It has a consensus weight of 1.000000%"),
            ]
        );
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].used, 1.0);
        assert!(!rg.use_counts.contains_key("XYZ"));
        // 100 of 1000 at a churn weight of 1%: 10% against a 5% allowance.
        let mut rg = Rendguard::default();
        rg.xfer_use_counts(&[], &BTreeMap::new(), &mut s);
        rg.use_counts.get_mut(NOT_IN_CONSENSUS_ID).unwrap().used = 99.0;
        rg.total_use_counts = 999.0;
        s.logs.clear();
        assert!(!rg.valid_rend_use("XYZ", &mut s));
        assert!(s.has(
            Level::Notice,
            "Relay XYZ (not in-consensus) used 100 times out of 1000, for a use rate of 10.000000%. This is above its consensus weight of 1.000000%"
        ));
    }

    #[test]
    fn rendguard_circ_event_only_judges_service_rend_points_being_connected() {
        let line = |status: &str, purpose: &str, hs: &str| {
            format!("650 CIRC 5 {status} {G},{R} PURPOSE={purpose} HS_STATE={hs}")
        };
        for (status, purpose, hs) in [
            ("EXTENDED", "HS_SERVICE_REND", "HSSR_CONNECTING"),
            ("BUILT", "HS_CLIENT_REND", "HSSR_CONNECTING"),
            ("BUILT", "HS_SERVICE_REND", "HSSR_JOINED"),
            ("BUILT", "GENERAL", "HSSR_CONNECTING"),
        ] {
            let mut s = Rec::default();
            let mut rg = Rendguard::default();
            let l5 = line(status, purpose, hs);
            rg.circ_event(&evt(&l5, 1.0), &mut s);
            assert_eq!(rg.total_use_counts, 0.0, "{l5}");
            assert!(s.closes.is_empty());
            assert_eq!(s.logs, vec![l(Level::Debug, &l5)]);
        }
        // No hops at all: nothing to judge.
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        rg.circ_event(
            &evt(
                "650 CIRC 5 BUILT PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING",
                1.0,
            ),
            &mut s,
        );
        assert_eq!(rg.total_use_counts, 0.0);
        // The rend point is the last hop, and it is counted.
        let ok = line("BUILT", "HS_SERVICE_REND", "HSSR_CONNECTING");
        rg.circ_event(&evt(&ok, 1.0), &mut s);
        assert_eq!(rg.total_use_counts, 1.0);
        assert!(s.has(
            Level::Info,
            &format!("Relay {} is not in our consensus.", fp('B'))
        ));
        assert!(s.closes.is_empty());
        // An overused rend point gets its circuit closed.
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        rg.use_counts.insert(
            fp('B'),
            UseCount {
                used: 499.0,
                weight: 0.1,
            },
        );
        rg.total_use_counts = 999.0;
        rg.circ_event(&evt(&ok, 1.0), &mut s);
        assert!(s.closes.is_empty());
        rg.circ_event(&evt(&ok, 1.0), &mut s);
        assert_eq!(s.closes, vec!["5"]);
    }

    fn rt(c: char, flags: &[&str], measured: f64) -> Router {
        Router {
            fingerprint: fp(c),
            flags: flags.iter().map(|f| f.to_string()).collect(),
            measured,
        }
    }

    fn consensus_weights() -> BTreeMap<String, f64> {
        // Distinct values, so a mixed-up position or flag changes the result.
        [
            ("Wmm", 10000.0),
            ("Wmg", 5000.0),
            ("Wme", 2000.0),
            ("Wmd", 4000.0),
            ("Wee", 5000.0),
            ("Wed", 2500.0),
            ("Weg", 7000.0),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    fn near(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    #[test]
    fn use_weights_follow_the_flags_and_the_consensus_bandwidth_weights() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        let routers = vec![
            rt('1', &["Fast", "Valid"], 100.0),
            rt('2', &["Fast", "Valid", "Guard"], 200.0),
            rt('3', &["Fast", "Valid", "Exit"], 300.0),
            rt('4', &["Fast", "Valid", "Guard", "Exit"], 400.0),
            rt('5', &["Fast", "Valid", "Authority"], 500.0),
            rt('6', &["Fast"], 600.0),
            rt('7', &["Valid"], 700.0),
        ];
        rg.xfer_use_counts(&routers, &consensus_weights(), &mut s);
        // Middle weights: 100 x 1.0, 200 x 0.5, 300 x 0.2, 400 x 0.4 = 420 in all.
        // Exits are re-weighted for the exit position: 300 x 0.5 and 400 x 0.25 = 250.
        let want = [
            ('1', 100.0 / 420.0),
            ('2', 100.0 / 420.0),
            ('3', 150.0 / 250.0),
            ('4', 100.0 / 250.0),
            ('5', 0.0),
            ('6', 0.0),
            ('7', 0.0),
        ];
        for (c, w) in want {
            assert!(
                near(rg.use_counts[&fp(c)].weight, w),
                "{c}: {}",
                rg.use_counts[&fp(c)].weight
            );
            assert_eq!(rg.use_counts[&fp(c)].used, 0.0);
        }
        assert_eq!(rg.use_counts.len(), 8);
        // Churn: 1% of the network is allowed to be unknown.
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].weight, 0.01);
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].used, 0.0);
        assert_eq!(rg.total_use_counts, 0.0);
        assert!(s.logs.is_empty());
    }

    #[test]
    fn use_weights_are_zero_when_the_consensus_has_no_weight() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        let routers = vec![
            rt('1', &["Fast", "Valid"], 100.0),
            rt('3', &["Fast", "Valid", "Exit"], 300.0),
        ];
        // No bandwidth-weights at all: every total is zero, and the weights are 0, not NaN.
        rg.xfer_use_counts(&routers, &BTreeMap::new(), &mut s);
        for c in ['1', '3'] {
            assert_eq!(rg.use_counts[&fp(c)].weight, 0.0, "{c}");
        }
        // Weights only for the exit position: the middle total is zero but the exit total is not.
        let only_exit: BTreeMap<String, f64> = [("Wee".to_string(), 10000.0)].into_iter().collect();
        rg.xfer_use_counts(&routers, &only_exit, &mut s);
        assert_eq!(rg.use_counts[&fp('1')].weight, 0.0);
        assert!(near(rg.use_counts[&fp('3')].weight, 1.0));
    }

    #[test]
    fn use_counts_carry_over_to_the_next_consensus() {
        let mut s = Rec::default();
        let routers = vec![
            rt('1', &["Fast", "Valid"], 100.0),
            rt('2', &["Fast", "Valid"], 100.0),
        ];
        let with = |total: f64| {
            let mut rg = Rendguard::default();
            rg.use_counts.insert(
                fp('1'),
                UseCount {
                    used: 10.0,
                    weight: 0.3,
                },
            );
            rg.use_counts.insert(
                "GONE".into(),
                UseCount {
                    used: 5.0,
                    weight: 0.3,
                },
            );
            rg.use_counts.insert(
                NOT_IN_CONSENSUS_ID.into(),
                UseCount {
                    used: 4.0,
                    weight: 0.5,
                },
            );
            rg.total_use_counts = total;
            rg
        };
        let mut rg = with(19999.0);
        rg.xfer_use_counts(&routers, &consensus_weights(), &mut s);
        assert!(s.logs.is_empty());
        assert_eq!(rg.use_counts[&fp('1')].used, 10.0);
        assert_eq!(rg.use_counts[&fp('2')].used, 0.0);
        assert!(!rg.use_counts.contains_key("GONE"));
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].used, 4.0);
        // The new churn weight replaces the old one.
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].weight, 0.01);
        assert!(near(rg.use_counts[&fp('1')].weight, 0.5));
        assert_eq!(rg.total_use_counts, 14.0);
        // At 20000 uses all counts are halved, once.
        let mut rg = with(20000.0);
        rg.xfer_use_counts(&routers, &consensus_weights(), &mut s);
        assert_eq!(
            s.logs,
            vec![l(
                Level::Info,
                "Total use counts 20000 reached the scale count 20000. Scaling."
            )]
        );
        assert_eq!(rg.use_counts[&fp('1')].used, 5.0);
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].used, 2.0);
        assert_eq!(rg.total_use_counts, 7.0);
        // Without a not-in-consensus entry the new one starts empty.
        let mut rg = Rendguard::default();
        rg.xfer_use_counts(&routers, &consensus_weights(), &mut s);
        assert_eq!(rg.use_counts[NOT_IN_CONSENSUS_ID].used, 0.0);
    }

    // ── G6: consensus parsing ───────────────────────────────────────────────

    #[test]
    fn ns_lines_give_flags_and_measured_bandwidth() {
        let id = "AAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 27 chars: 20 bytes of zero
        let body = format!(
            "r a {id} d 2026-01-01 00:00:00 1.2.3.4 9001 0\ns Fast Guard Valid\nw Bandwidth=123 Measured=456\n\
             r b {id} d 2026-01-01 00:00:00 1.2.3.4 9001 0\ns Exit\nw Bandwidth=7\n\
             r d {id} d 2026-01-01 00:00:00 1.2.3.4 9001 0\ns Fast"
        );
        let r = parse_ns(&body);
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|x| x.fingerprint == "0".repeat(40)));
        assert_eq!(r[0].flags, vec!["Fast", "Guard", "Valid"]);
        assert_eq!(r[0].measured, 456.0);
        assert_eq!(
            (r[1].flags.clone(), r[1].measured),
            (vec!["Exit".to_string()], 7.0)
        );
        assert_eq!(
            (r[2].flags.clone(), r[2].measured),
            (vec!["Fast".to_string()], 0.0)
        );
    }

    #[test]
    fn bandwidth_weights_line_is_a_map() {
        let w =
            parse_weights("a b\nbandwidth-weights Wmm=10000 Wme=2500 junk Wxx=nope\nz").unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!((w["Wmm"], w["Wme"]), (10000.0, 2500.0));
        assert!(parse_weights("no weights here").is_none());
    }

    // ── G8: the control link ────────────────────────────────────────────────

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_line_strips_the_line_ending_and_reports_a_closed_peer() {
        let (mut link, mut peer) = link_pair();
        peer.write_all(b"250 OK\r\nplain\n\r\n").unwrap();
        assert_eq!(link.read_line().unwrap(), "250 OK");
        assert_eq!(link.read_line().unwrap(), "plain");
        assert_eq!(link.read_line().unwrap(), "");
        drop(peer);
        let e = link.read_line().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_line_refuses_a_line_one_byte_over_the_cap() {
        // 1 MiB of text plus the newline is one over: the cap is on the line,
        // and a line exactly at the cap (tested above) is fine.
        let mut line = vec![b'a'; 1 << 20];
        line.push(b'\n');
        let (mut link, _feeder) = link_fed(line);
        let e = link.read_line().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{e}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_message_reads_single_and_multi_line_replies() {
        let (mut link, mut peer) = link_pair();
        peer.write_all(b"250 \r\n250-version=0.4.9\r\n250-more=1\r\n250 OK\r\n")
            .unwrap();
        assert_eq!(
            link.read_message().unwrap(),
            ("250".to_string(), vec!["250 ".to_string()])
        );
        let (code, lines) = link.read_message().unwrap();
        assert_eq!(code, "250");
        assert_eq!(lines, vec!["250-version=0.4.9", "250-more=1", "250 OK"]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_message_rejects_lines_without_a_status_and_separator() {
        for bad in [&b"250\r\n"[..], b"\r\n", b"25\r\n"] {
            let (mut link, mut peer) = link_pair();
            peer.write_all(bad).unwrap();
            let e = link.read_message().unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidData, "{bad:?}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_message_collects_data_blocks_and_unstuffs_dots() {
        let (mut link, mut peer) = link_pair();
        peer.write_all(b"250+ns/all=\r\nr first\r\n..hidden\r\nplain\r\n.\r\n250 OK\r\n")
            .unwrap();
        let (code, lines) = link.read_message().unwrap();
        assert_eq!(code, "250");
        assert_eq!(
            lines,
            vec!["250+ns/all=", "r first", ".hidden", "plain", "250 OK"]
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn command_sends_one_line_and_queues_events_that_arrive_first() {
        let (mut link, mut peer) = link_pair();
        let ev_line = format!("650 CIRC 5 BUILT {G},{R} PURPOSE=GENERAL");
        peer.write_all(format!("{ev_line}\r\n250 OK\r\n").as_bytes())
            .unwrap();
        let (code, lines) = link.command("SETEVENTS CIRC").unwrap();
        assert_eq!((code.as_str(), lines), ("250", vec!["250 OK".to_string()]));
        assert_eq!(link.pending.len(), 1);
        assert_eq!(link.pending[0].raw, ev_line);
        assert!((link.pending[0].arrived_at - now()).abs() < 5.0);
        let mut got = [0u8; 16];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"SETEVENTS CIRC\r\n");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn getinfo_returns_the_value_or_the_data_block() {
        let (mut link, mut peer) = link_pair();
        peer.write_all(b"250-version=0.4.9.16\r\n250 OK\r\n")
            .unwrap();
        assert_eq!(link.getinfo("version").unwrap(), "0.4.9.16");
        peer.write_all(b"250+ns/all=\r\nr a\r\ns Fast\r\n.\r\n250 OK\r\n")
            .unwrap();
        assert_eq!(link.getinfo("ns/all").unwrap(), "r a\ns Fast");
        peer.write_all(b"552 Unrecognized key \"nope\"\r\n")
            .unwrap();
        let e = link.getinfo("nope").unwrap_err();
        assert!(e.to_string().contains("Unrecognized key"), "{e}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn flush_closes_reports_what_tor_answered() {
        let (mut link, mut peer) = link_pair();
        peer.write_all(b"250 OK\r\n552 Unknown circuit \"6\"\r\n")
            .unwrap();
        let mut s = Rec::default();
        flush_closes(&mut link, vec!["5".into(), "6".into()], &mut s).unwrap();
        assert_eq!(
            s.logs,
            vec![
                l(Level::Notice, "We force-closed circuit 5"),
                l(
                    Level::Info,
                    "Failed to close circuit 6: Unknown circuit \"6\""
                ),
            ]
        );
        let want = b"CLOSECIRCUIT 5\r\nCLOSECIRCUIT 6\r\n";
        let mut got = vec![0u8; want.len()];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(got, want);
        // Nothing to close, nothing sent.
        let mut s = Rec::default();
        flush_closes(&mut link, vec![], &mut s).unwrap();
        assert!(s.logs.is_empty());
    }

    // ── G9: dispatch ────────────────────────────────────────────────────────

    #[test]
    fn dispatch_event_routes_each_kind_to_its_guard() {
        let mut s = Rec::default();
        let mut rg = Rendguard::default();
        let mut b = Bandguards::new(&format!("{G} CONNECTED"), "up", 900.0, &mut s);
        let go = |line: &str, at: f64, rg: &mut Rendguard, b: &mut Bandguards, s: &mut Rec| {
            dispatch_event(&evt(line, at), rg, b, s);
        };
        // CIRC goes to both: rendguard counts the rend point, bandguards tracks the circuit.
        go(
            &format!("650 CIRC 5 BUILT {G},{R} PURPOSE=HS_SERVICE_REND HS_STATE=HSSR_CONNECTING"),
            901.0,
            &mut rg,
            &mut b,
            &mut s,
        );
        assert_eq!(rg.total_use_counts, 1.0);
        assert!(b.circs.contains_key("5"));
        // CIRC_MINOR: bandguards only.
        go(&format!("650 CIRC_MINOR 5 PURPOSE_CHANGED {G},{R} PURPOSE=PATH_BIAS_TESTING OLD_PURPOSE=HS_VANGUARDS"), 902.0, &mut rg, &mut b, &mut s);
        assert_eq!(b.circs["5"].purpose.as_deref(), Some("PATH_BIAS_TESTING"));
        assert_eq!(rg.total_use_counts, 1.0);
        // CIRC_BW.
        go(
            &bw_line("5", 100, 7, 0, 0, 0, 0),
            903.0,
            &mut rg,
            &mut b,
            &mut s,
        );
        assert_eq!(b.circs["5"].read_bytes, 100.0);
        // NETWORK_LIVENESS.
        go("650 NETWORK_LIVENESS DOWN", 904.0, &mut rg, &mut b, &mut s);
        assert_eq!(b.network_down_since, Some(904.0));
        // ORCONN, then BW (which looks at the outage).
        go(
            &format!("650 ORCONN {G} CLOSED ID=0"),
            1000.0,
            &mut rg,
            &mut b,
            &mut s,
        );
        assert!(b.live_guard_conns.is_empty());
        s.logs.clear();
        go("650 BW 1 1", 1020.0, &mut rg, &mut b, &mut s);
        assert!(s.has(
            Level::Warn,
            "We've been disconnected from the Tor network for 20 seconds!"
        ));
        // Kinds nobody subscribes to are dropped without a trace.
        s.logs.clear();
        let (circs, total) = (b.circs.len(), rg.total_use_counts);
        go(
            "650 STREAM 1 NEW 0 example.com:80",
            1021.0,
            &mut rg,
            &mut b,
            &mut s,
        );
        go("650 SIGNAL RELOAD", 1022.0, &mut rg, &mut b, &mut s);
        assert!(s.logs.is_empty());
        assert_eq!((b.circs.len(), rg.total_use_counts), (circs, total));
    }
}
