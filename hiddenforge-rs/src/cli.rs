//! The in-image operator commands (`docker run <image> <cmd>`, and
//! `docker exec <c> hiddenforge <cmd>`): ports of scripts/hiddenforge's
//! version, info, show, doctor --keys-only, setup, rotate, the key-archive
//! commands, and vanity.py. Output, JSON and exit codes are 2.1.6's.

use crate::fsops;
use crate::py::{self, Json};
use crate::sha3;
use std::ffi::CString;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CONTRACT_VERSION: i64 = 1;
const DEFAULT_CONTAINER: &str = "tor";
const DEFAULT_NAME: &str = "myapp";
const DEFAULT_KEYS: &str = "./tor-keys";
const MANIFEST: &str = "/opt/hiddenforge/manifest.json";
const TORRC_PATH: &str = "/etc/tor/torrc";
const SECRET_FILE: &str = "hs_ed25519_secret_key";
const PUBLIC_FILE: &str = "hs_ed25519_public_key";
const HOSTNAME_FILE: &str = "hostname";
const PUBLIC_TAG: &[u8] = b"== ed25519v1-public: type0 ==";

const EXIT_OK: i32 = 0;
const EXIT_FAIL: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_RACE: i32 = 3;
const EXIT_NOT_READY: i32 = 4;
const EXIT_ABORTED: i32 = 130;

fn default_image() -> String {
    std::env::var("HIDDENFORGE_IMAGE").unwrap_or_else(|_| "sambent.dev/sam/hiddenforge:latest".into())
}

fn default_keys_env() -> String {
    std::env::var("HIDDENFORGE_KEYS_DIR").unwrap_or_else(|_| DEFAULT_KEYS.into())
}

// ───────────────────────────── argument parsing ─────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Flag,
    Value,
    Append,
}

struct Opt {
    long: &'static str,
    short: Option<&'static str>,
    kind: Kind,
    required: bool,
    choices: &'static [&'static str],
    int: bool,
}

const fn o(long: &'static str, kind: Kind) -> Opt {
    Opt { long, short: None, kind, required: false, choices: &[], int: false }
}

#[derive(Default, Debug)]
pub struct Args {
    vals: Vec<(String, String)>,
    flags: Vec<String>,
    appends: Vec<(String, Vec<String>)>,
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.vals.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
    fn list(&self, k: &str) -> Option<&Vec<String>> {
        self.appends.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }
}

fn dest(long: &str) -> String {
    long.trim_start_matches('-').replace('-', "_")
}

/// argparse-compatible parsing: `--opt v`, `--opt=v`, unique-prefix abbreviations.
fn parse(prog: &str, specs: &[Opt], argv: &[String]) -> Result<Args, i32> {
    let mut a = Args::default();
    let usage = || {
        let mut u = format!("usage: {prog} [-h]");
        for s in specs {
            let meta = dest(s.long).to_uppercase();
            let item = match s.kind {
                Kind::Flag => s.long.to_string(),
                _ => format!("{} {meta}", s.long),
            };
            if s.required {
                u.push_str(&format!(" {item}"));
            } else {
                u.push_str(&format!(" [{item}]"));
            }
        }
        u
    };
    let fail = |msg: String| -> i32 {
        eprintln!("{}", usage());
        eprintln!("{prog}: error: {msg}");
        EXIT_USAGE
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        if arg == "-h" || arg == "--help" {
            println!("{}", usage());
            std::process::exit(0);
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let matches: Vec<&Opt> = if name.starts_with("--") {
            match specs.iter().find(|s| s.long == name) {
                Some(s) => vec![s],
                None => specs.iter().filter(|s| s.long.starts_with(&name)).collect(),
            }
        } else if name.starts_with('-') && name.len() > 1 {
            specs.iter().filter(|s| s.short == Some(name.as_str())).collect()
        } else {
            vec![]
        };
        let spec = match matches.as_slice() {
            [s] => *s,
            [] => return Err(fail(format!("unrecognized arguments: {}", argv[i..].join(" ")))),
            many => {
                let names: Vec<&str> = many.iter().map(|s| s.long).collect();
                return Err(fail(format!("ambiguous option: {name} could match {}", names.join(", "))));
            }
        };
        let d = dest(spec.long);
        match spec.kind {
            Kind::Flag => {
                if inline.is_some() {
                    return Err(fail(format!("argument {}: ignored explicit argument '{}'", spec.long, inline.unwrap_or_default())));
                }
                a.flags.push(d);
            }
            Kind::Value | Kind::Append => {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        match argv.get(i) {
                            Some(v) if !(v.starts_with('-') && v.len() > 1 && !v[1..].starts_with(|c: char| c.is_ascii_digit())) => v.clone(),
                            _ => return Err(fail(format!("argument {}: expected one argument", spec.long))),
                        }
                    }
                };
                if !spec.choices.is_empty() && !spec.choices.contains(&v.as_str()) {
                    let ch: Vec<String> = spec.choices.iter().map(|c| format!("'{c}'")).collect();
                    return Err(fail(format!("argument {}: invalid choice: '{v}' (choose from {})", spec.long, ch.join(", "))));
                }
                if spec.int && v.trim().parse::<i64>().is_err() {
                    return Err(fail(format!("argument {}: invalid int value: '{v}'", spec.long)));
                }
                if spec.kind == Kind::Append {
                    match a.appends.iter_mut().find(|(n, _)| *n == d) {
                        Some((_, l)) => l.push(v),
                        None => a.appends.push((d, vec![v])),
                    }
                } else {
                    a.vals.push((d, v));
                }
            }
        }
        i += 1;
    }
    let missing: Vec<&str> = specs.iter().filter(|s| s.required && a.get(&dest(s.long)).is_none()).map(|s| s.long).collect();
    if !missing.is_empty() {
        return Err(fail(format!("the following arguments are required: {}", missing.join(", "))));
    }
    Ok(a)
}

fn int_arg(a: &Args, k: &str, default: i64) -> i64 {
    a.get(k).and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

// ───────────────────────────── shared helpers ───────────────────────────────

fn emit_json(rc: i32, fields: Vec<(&str, Json)>) -> i32 {
    let mut doc = Json::obj().with("ok", (rc == 0).into()).with("exit_code", Json::Int(i64::from(rc)));
    for (k, v) in fields {
        doc.set(k, v);
    }
    println!("{}", py::dumps(&doc, true, None));
    rc
}

/// str(pathlib.PurePosixPath(s)).
pub fn py_path(s: &str) -> String {
    if s.is_empty() {
        return ".".into();
    }
    let lead = if s.starts_with("//") && !s.starts_with("///") {
        "//"
    } else if s.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    let body = parts.join("/");
    if lead.is_empty() && body.is_empty() {
        ".".into()
    } else {
        format!("{lead}{body}")
    }
}

fn join(base: &str, name: &str) -> String {
    let b = py_path(base);
    if b == "." {
        name.to_string()
    } else if b.ends_with('/') {
        format!("{b}{name}")
    } else {
        format!("{b}/{name}")
    }
}

fn is_dir(p: &str) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_dir())
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.as_bytes()[0].is_ascii_lowercase() | n.as_bytes()[0].is_ascii_digit()
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn validate_name(n: &str) -> Result<String, String> {
    if !name_ok(n) {
        return Err(format!(
            "invalid service name {}: lowercase letters, digits and hyphens only, must start alphanumeric, max 63 chars (it becomes a directory under the key volume)",
            py::py_repr(n)
        ));
    }
    Ok(n.to_string())
}

fn validate_container(n: &str) -> Result<String, String> {
    let ok = !n.is_empty()
        && n.as_bytes()[0].is_ascii_alphanumeric()
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok {
        Ok(n.to_string())
    } else {
        Err(format!("invalid container name {}", py::py_repr(n)))
    }
}

fn container_ok(n: &str) -> bool {
    validate_container(n).is_ok()
}

fn validate_keys_dir(v: &str) -> Result<String, String> {
    if v.is_empty() || v.chars().count() > 4096 {
        return Err("key directory path must be 1-4096 characters".into());
    }
    if let Some(c) = v.chars().find(|c| (*c as u32) < 0x20 || *c as u32 == 0x7f) {
        return Err(format!(
            "key directory path contains a control character ({}); it is written into a compose file and a shell script",
            py::py_repr(&c.to_string())
        ));
    }
    Ok(v.to_string())
}

fn validate_image_ref(v: &str) -> Result<String, String> {
    let ok = !v.is_empty()
        && v.len() <= 255
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'-'));
    if ok {
        Ok(v.to_string())
    } else {
        Err(format!(
            "invalid image reference {}: expected registry/name[:tag][@sha256:...] with no spaces, newlines, or leading '-'",
            py::py_repr(v)
        ))
    }
}

/// _read_nofollow: regular files only, size-capped, no symlink, no FIFO block.
fn read_nofollow(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let fd = fsops::open(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0).map_err(|e| e.msg)?;
    let st = fsops::fstat(&fd).map_err(|e| e.msg)?;
    if !fsops::is_type(&st, libc::S_IFREG) {
        return Err(format!("{path} is not a regular file"));
    }
    if st.st_size as u64 > max {
        return Err(format!("{path} is unexpectedly large ({} bytes)", st.st_size));
    }
    let mut data = vec![0u8; st.st_size as usize];
    let mut got = 0;
    while got < data.len() {
        // SAFETY: reading into the unfilled tail of a live buffer.
        let n = unsafe { libc::read(fd.0, data[got..].as_mut_ptr().cast(), data.len() - got) };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    data.truncate(got);
    Ok(data)
}

fn read_onion_file(path: &str) -> Option<String> {
    let d = read_nofollow(path, 256).ok()?;
    if !d.is_ascii() {
        return None;
    }
    let t = py::strip_str(std::str::from_utf8(&d).ok()?).to_string();
    fsops::is_onion(&t).then_some(t)
}

fn read_pubkey(path: &str) -> Option<Vec<u8>> {
    let d = read_nofollow(path, 8192).ok()?;
    if d.len() == 64 && d.starts_with(PUBLIC_TAG) {
        return Some(d[32..].to_vec());
    }
    (d.len() == 32).then_some(d)
}

struct Entry {
    name: String,
    onion: Option<String>,
    source: Option<String>,
    derived_matches: Option<bool>,
    hostname_onion: Option<String>,
    derived_onion: Option<String>,
    key_path: String,
    public_key_path: String,
    address_path: String,
    key_dir: String,
}

impl Entry {
    fn json(&self) -> Json {
        let mut j = Json::obj()
            .with("name", self.name.as_str().into())
            .with("onion", self.onion.clone().into())
            .with("source", self.source.clone().into())
            .with("derived_matches", self.derived_matches.into());
        if self.derived_matches == Some(false) {
            j.set("hostname_onion", self.hostname_onion.clone().into());
            j.set("derived_onion", self.derived_onion.clone().into());
        }
        j.with("key_path", self.key_path.as_str().into())
            .with("public_key_path", self.public_key_path.as_str().into())
            .with("address_path", self.address_path.as_str().into())
            .with("key_dir", self.key_dir.as_str().into())
    }
    fn fields(&self) -> Vec<(&'static str, Json)> {
        let Json::Obj(items) = self.json() else { return vec![] };
        items.into_iter().map(|(k, v)| (leak(k), v)).collect()
    }
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn address_for(keys: &str, name: &str) -> Entry {
    let d = join(keys, name);
    let published = join(keys, &format!("{name}.onion"));
    let mut onion = read_onion_file(&format!("{d}/{HOSTNAME_FILE}"));
    let mut source = Some("hostname".to_string());
    if onion.is_none() {
        onion = read_onion_file(&published);
        source = Some("published".into());
    }
    let derived = read_pubkey(&format!("{d}/{PUBLIC_FILE}")).and_then(|k| sha3::derive_onion(&k));
    if onion.is_none() {
        if let Some(dv) = &derived {
            onion = Some(dv.clone());
            source = Some("derived".into());
        } else {
            source = None;
        }
    }
    let derived_matches = match (&derived, &onion) {
        (Some(dv), Some(on)) => Some(dv == on),
        _ => None,
    };
    let (mut hostname_onion, mut derived_onion) = (None, None);
    if derived_matches == Some(false) {
        hostname_onion = onion.take();
        derived_onion = derived.clone();
        source = Some("inconsistent".into());
    }
    Entry {
        name: name.to_string(),
        onion,
        source,
        derived_matches,
        hostname_onion,
        derived_onion,
        key_path: format!("{d}/{SECRET_FILE}"),
        public_key_path: format!("{d}/{PUBLIC_FILE}"),
        address_path: published,
        key_dir: d,
    }
}

fn hsdir_value(line: &str) -> Option<String> {
    let t = line.trim_start_matches(char::is_whitespace);
    let rest = t.strip_prefix("HiddenServiceDir")?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let rest = rest.trim_start_matches(char::is_whitespace);
    let val: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
    (!val.is_empty() && rest[val.len()..].chars().all(char::is_whitespace)).then_some(val)
}

fn torrc_service_names(keys: &str) -> Vec<String> {
    let Ok(b) = std::fs::read(TORRC_PATH) else { return vec![] };
    let text = String::from_utf8_lossy(&b);
    let mut names = Vec::new();
    for line in text.lines() {
        let Some(v) = hsdir_value(line) else { continue };
        let p = py_path(&v);
        let (parent, name) = p.rsplit_once('/').unwrap_or(("", p.as_str()));
        let parent = if parent.is_empty() && p.starts_with('/') { "/" } else { parent };
        if py_path(parent) == py_path(keys) && name_ok(name) && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

fn service_names(keys: &str) -> Vec<String> {
    if !is_dir(keys) {
        return vec![];
    }
    let rd = match std::fs::read_dir(keys) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return torrc_service_names(keys),
        Err(_) => return vec![],
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| name_ok(n))
        .collect();
    names.sort();
    names
}

fn in_container() -> bool {
    std::env::var("HIDDENFORGE_IN_CONTAINER").as_deref() == Ok("1") || std::path::Path::new(TORRC_PATH).exists()
}

fn no_tool_error() -> String {
    let mut m = "no encryption tool found: install `age` (preferred) or `gpg`".to_string();
    if in_container() {
        m += ". The hiddenforge image ships no crypto tooling on purpose; run this command on the HOST that holds your backup, not with docker exec";
    }
    m
}

fn which(tool: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|d| !d.is_empty() && access(&format!("{d}/{tool}"), libc::X_OK) && !is_dir(&format!("{d}/{tool}")))
}

fn access(path: &str, mode: i32) -> bool {
    let Ok(c) = CString::new(path) else { return false };
    // SAFETY: valid C string.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

fn stdin_tty() -> bool {
    // SAFETY: isatty on fd 0.
    unsafe { libc::isatty(0) == 1 }
}

// ───────────────────────────── commands ─────────────────────────────────────

fn cmd_version(a: &Args) -> i32 {
    if a.flag("json") {
        return emit_json(
            EXIT_OK,
            vec![("name", "hiddenforge".into()), ("version", VERSION.into()), ("contract_version", Json::Int(CONTRACT_VERSION))],
        );
    }
    println!("hiddenforge {VERSION} (contract {CONTRACT_VERSION})");
    EXIT_OK
}

fn cmd_info(a: &Args) -> i32 {
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_default();
    let Some(m) = py::parse(&text) else {
        return emit_json(EXIT_FAIL, vec![("error", format!("cannot read {MANIFEST}").into())]);
    };
    if a.flag("json") {
        println!("{}", py::dumps(&m, true, Some(2)));
        return EXIT_OK;
    }
    let s = |j: Option<&Json>| match j {
        Some(Json::Str(s)) => s.clone(),
        Some(Json::Int(i)) => i.to_string(),
        _ => String::new(),
    };
    let vol = match m.get("volumes") {
        Some(Json::Arr(v)) => v.first().cloned().unwrap_or(Json::Null),
        _ => Json::Null,
    };
    println!("{} {} (contract {})", s(m.get("name")), s(m.get("version")), s(m.get("contract_version")));
    println!("  image:   {}", s(m.get("image")));
    println!("  tor:     {}", s(m.get("tor_version")));
    println!("  address: {}", s(m.get("address").and_then(|x| x.get("command"))));
    println!(
        "  health:  {} (field: {})",
        s(m.get("health").and_then(|x| x.get("command"))),
        s(m.get("health").and_then(|x| x.get("ready_field")))
    );
    println!("  keys:    {} -> {}", s(vol.get("path")), s(vol.get("host_suggestion")));
    EXIT_OK
}

fn not_ready_error(keys: &str, name: &str) -> String {
    let d = join(keys, name);
    if !is_dir(&d) {
        return "address not generated yet (no key directory for this service)".into();
    }
    if !access(&d, libc::R_OK | libc::X_OK) {
        return format!(
            "address not published yet: {d} exists but is not readable by this user, and {} does not exist. Under Docker it appears once the service is reachable. Under rootless Podman it is never written; pass --container <name> to read the address from inside the container.",
            join(keys, &format!("{name}.onion"))
        );
    }
    "address not generated yet (Tor has not written hostname)".into()
}

fn inconsistent_error(e: &Entry) -> String {
    format!(
        "{}: the hostname file says {} but the public key is {}. Tor serves the key's address and rewrites hostname at startup, so the file is wrong. The directory holds files from two key sets (a partial restore or copy): restore the whole directory from one backup before publishing any address.",
        e.name,
        e.hostname_onion.clone().unwrap_or_else(|| "None".into()),
        e.derived_onion.clone().unwrap_or_else(|| "None".into())
    )
}

fn cmd_show(a: &Args) -> i32 {
    let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
    if let Some(c) = a.get("container") {
        if let Err(e) = validate_container(c) {
            return emit_json(EXIT_USAGE, vec![("error", e.into())]);
        }
        // Inside the image there is no engine to ask; the container IS here.
    }
    if let Some(name) = a.get("name") {
        if let Err(e) = validate_name(name) {
            return emit_json(EXIT_USAGE, vec![("error", e.into())]);
        }
        let e = address_for(&keys, name);
        if e.source.as_deref() == Some("inconsistent") {
            let mut f = e.fields();
            f.push(("keys", keys.as_str().into()));
            f.push(("error", inconsistent_error(&e).into()));
            return emit_json(EXIT_FAIL, f);
        }
        if e.onion.is_none() {
            return emit_json(
                EXIT_NOT_READY,
                vec![
                    ("name", name.into()),
                    ("onion", Json::Null),
                    ("key_path", e.key_path.as_str().into()),
                    ("keys", keys.as_str().into()),
                    ("error", not_ready_error(&keys, name).into()),
                ],
            );
        }
        if a.flag("json") {
            return emit_json(EXIT_OK, e.fields());
        }
        println!("{} {}", e.name, e.onion.unwrap_or_default());
        return EXIT_OK;
    }
    let entries: Vec<Entry> = service_names(&keys).iter().map(|n| address_for(&keys, n)).collect();
    if !is_dir(&keys) {
        return emit_json(EXIT_USAGE, vec![("keys", keys.as_str().into()), ("error", format!("key directory {keys} does not exist").into())]);
    }
    if entries.is_empty() {
        return emit_json(
            EXIT_USAGE,
            vec![
                ("keys", keys.as_str().into()),
                ("error", format!("cannot enumerate services in {keys} (the key volume is 0751, traverse-only); pass --name <service>").into()),
            ],
        );
    }
    let inconsistent: Vec<&Entry> = entries.iter().filter(|e| e.source.as_deref() == Some("inconsistent")).collect();
    let rc = if !inconsistent.is_empty() {
        EXIT_FAIL
    } else if !entries.iter().all(|e| e.onion.is_some()) {
        EXIT_NOT_READY
    } else {
        EXIT_OK
    };
    if a.flag("json") {
        let mut f = vec![
            ("keys", keys.as_str().into()),
            ("addresses", Json::Arr(entries.iter().map(Entry::json).collect())),
            ("address", entries[0].onion.clone().into()),
        ];
        if !inconsistent.is_empty() {
            let msgs: Vec<String> = inconsistent.iter().map(|e| inconsistent_error(e)).collect();
            f.push(("error", msgs.join("; ").into()));
        }
        return emit_json(rc, f);
    }
    for e in &entries {
        if e.source.as_deref() == Some("inconsistent") {
            println!("{} (INCONSISTENT KEY SET - no address reported)", e.name);
            eprintln!("error: {}", inconsistent_error(e));
        } else {
            println!("{} {}", e.name, e.onion.clone().unwrap_or_else(|| "(not generated yet)".into()));
        }
    }
    rc
}

fn check(ok: bool, name: &str, detail: &str, severity: &str) -> Json {
    Json::obj()
        .with("check", name.into())
        .with("ok", ok.into())
        .with("detail", detail.into())
        .with("severity", severity.into())
}

fn oct(m: u32) -> String {
    format!("0o{m:o}")
}

fn cmd_doctor(a: &Args) -> i32 {
    let container = a.get("container").unwrap_or(DEFAULT_CONTAINER);
    if let Err(e) = validate_container(container) {
        return emit_json(EXIT_USAGE, vec![("error", e.into())]);
    }
    // In the image there is no engine socket: on-disk key hygiene only (2.x
    // appended --keys-only for every in-image doctor).
    let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
    let mut checks: Vec<Json> = Vec::new();
    let mut closed: Vec<String> = Vec::new();
    if !is_dir(&keys) {
        checks.push(check(false, "key directory exists", &format!("{keys} not found"), "fail"));
    } else {
        let dirmode = fsops::lstat(&keys).map(|s| fsops::imode(&s)).unwrap_or(0);
        checks.push(check(
            dirmode & 0o026 == 0,
            "key volume is not group/world writable or world readable",
            &format!("mode={}", oct(dirmode)),
            "warn",
        ));
        let names = service_names(&keys);
        if names.is_empty() {
            checks.push(check(
                true,
                "service key directories checked",
                "key volume is not listable (0751 by design); run `docker exec <container> hiddenforge doctor --keys-only` to verify service dir/file modes",
                "warn",
            ));
        }
        for name in names {
            let d = join(&keys, &name);
            let modes = fsops::lstat(&d).and_then(|s| fsops::lstat(&format!("{d}/{SECRET_FILE}")).map(|k| (fsops::imode(&s), fsops::imode(&k))));
            match modes {
                Err(e) if e.is_permission() => closed.push(name),
                Err(e) => checks.push(check(false, &format!("key modes for {name}"), &format!("cannot stat: {}", e.msg), "fail")),
                Ok((dm, sm)) => {
                    checks.push(check(dm == 0o700, &format!("key dir {name} is 0700"), &format!("mode={}", oct(dm)), "fail"));
                    checks.push(check(sm == 0o600, &format!("secret key {name} is 0600"), &format!("mode={}", oct(sm)), "fail"));
                    let e = address_for(&keys, &name);
                    if e.derived_matches == Some(false) {
                        checks.push(check(
                            false,
                            &format!("{name}: hostname file matches the public key"),
                            &format!(
                                "hostname says {}, the public key is {}; Tor serves the key's address",
                                e.hostname_onion.clone().unwrap_or_default(),
                                e.derived_onion.clone().unwrap_or_default()
                            ),
                            "fail",
                        ));
                    }
                }
            }
        }
    }
    for name in &closed {
        checks.push(check(
            false,
            &format!("key modes for {name}"),
            "the service directory belongs to the container's tor user and the container could not be asked; run `docker exec <container> su-exec tor hiddenforge doctor --keys-only`",
            "warn",
        ));
    }
    let failures: Vec<String> = checks
        .iter()
        .filter(|c| c.get("ok") == Some(&Json::Bool(false)) && c.get("severity") == Some(&Json::Str("fail".into())))
        .filter_map(|c| match c.get("check") {
            Some(Json::Str(s)) => Some(s.clone()),
            _ => None,
        })
        .collect();
    let ok = failures.is_empty();
    let rc = if ok { EXIT_OK } else { EXIT_FAIL };
    if a.flag("json") {
        return emit_json(
            rc,
            vec![
                ("keys", keys.as_str().into()),
                ("ok", ok.into()),
                ("failures", Json::Arr(failures.into_iter().map(Json::Str).collect())),
                ("checks", Json::Arr(checks)),
            ],
        );
    }
    for c in &checks {
        let okc = c.get("ok") == Some(&Json::Bool(true));
        let s = |k| match c.get(k) {
            Some(Json::Str(s)) => s.clone(),
            _ => String::new(),
        };
        println!("[{}] {}: {}", if okc { "ok  " } else { "FAIL" }, s("check"), s("detail"));
    }
    rc
}

// ── setup ──

pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn yaml_dq(v: &str) -> String {
    let mut out = String::from("\"");
    for ch in v.chars() {
        let cp = ch as u32;
        if ch == '"' || ch == '\\' {
            out.push('\\');
            out.push(ch);
        } else if (0x20..0x7f).contains(&cp) {
            out.push(ch);
        } else if cp <= 0xFFFF {
            out.push_str(&format!("\\u{cp:04x}"));
        } else {
            out.push_str(&format!("\\U{cp:08x}"));
        }
    }
    out.push('"');
    out
}

fn env_var(n: &str) -> String {
    format!("{}_TOR_SERVICE_HOSTS", n.to_uppercase().replace('-', "_"))
}

fn is_ip_literal(v: &str) -> bool {
    v.parse::<std::net::IpAddr>().is_ok()
}

fn host_ok(h: &str) -> bool {
    (1..=253).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn py_isdigit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn port_ok(s: &str) -> bool {
    py_isdigit(s) && s.parse::<u64>().is_ok_and(|p| (1..=65535).contains(&p))
}

fn parse_backend(b: &str) -> Result<(String, String), String> {
    let Some((host, port)) = b.rsplit_once(':') else {
        return Err(format!("--backend must be host:port, got {}", py::py_repr(b)));
    };
    if host.is_empty() || !port_ok(port) {
        return Err(format!("--backend must be host:port with port 1-65535, got {}", py::py_repr(b)));
    }
    if !host_ok(host) {
        return Err(format!("invalid backend host {}", py::py_repr(host)));
    }
    Ok((host.into(), port.into()))
}

fn parse_service_spec(spec: &str) -> Result<(String, String), String> {
    let p: Vec<&str> = spec.split(':').collect();
    if p.len() != 4 {
        return Err(format!("service mapping must be name:onionport:host:port, got {}", py::py_repr(spec)));
    }
    let n = validate_name(p[0])?;
    if !port_ok(p[1]) {
        return Err(format!("bad onion port in {}", py::py_repr(spec)));
    }
    if !port_ok(p[3]) {
        return Err(format!("bad backend port in {}", py::py_repr(spec)));
    }
    if !host_ok(p[2]) {
        return Err(format!("invalid backend host in {}", py::py_repr(spec)));
    }
    Ok((n, format!("{}:{}:{}", p[1], p[2], p[3])))
}

type Services = Vec<(String, Vec<String>)>; // sorted by name when rendered

fn sorted(s: &Services) -> Services {
    let mut v = s.clone();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

pub struct SetupOpts<'a> {
    pub image: &'a str,
    pub keys: &'a str,
    pub container: &'a str,
    pub runtime: &'a str,
    pub no_root: bool,
}

fn render_compose(services: &Services, o: &SetupOpts) -> String {
    let svc = sorted(services);
    let env_lines: String = svc.iter().map(|(n, v)| format!("      {}: \"{}\"\n", env_var(n), v.join(","))).collect();
    let mut hosts: Vec<String> = svc
        .iter()
        .flat_map(|(_, m)| m.iter())
        .filter_map(|m| {
            let p: Vec<&str> = m.split(':').collect();
            (p.len() == 3).then(|| p[1].to_string())
        })
        .filter(|h| !h.is_empty())
        .collect();
    hosts.sort();
    hosts.dedup();
    let hosts: Vec<String> = hosts.into_iter().filter(|h| container_ok(h) && !is_ip_literal(h)).collect();
    let dep_block = if hosts.is_empty() {
        String::new()
    } else {
        format!("    depends_on:\n{}", hosts.iter().map(|h| format!("      - {h}\n")).collect::<String>())
    };
    let docker = o.runtime == "docker";
    let apparmor = if docker { "      - apparmor=docker-default\n" } else { "" };
    let mut tor_tmpfs = "- /var/lib/tor:rw,noexec,nosuid,nodev,size=64m".to_string();
    let mut etc_tmpfs = "- /etc/tor:rw,noexec,nosuid,nodev,size=8m".to_string();
    if docker {
        tor_tmpfs += ",uid=100,gid=101,mode=0700";
    }
    if o.no_root {
        if docker {
            etc_tmpfs += ",uid=100,gid=101";
        } else {
            tor_tmpfs += ",mode=0700,U";
            etc_tmpfs += ",U";
        }
    }
    let compose_cmd = if o.runtime == "podman" { "podman-compose" } else { "docker compose" };
    let restart = if o.runtime == "podman" { "always" } else { "unless-stopped" };
    let healthcheck = if o.runtime == "podman" {
        String::new()
    } else {
        "    healthcheck:\n      test: [\"CMD\", \"su-exec\", \"tor\", \"python3\", \"/usr/local/bin/healthcheck.py\"]\n      interval: 60s\n      timeout: 10s\n      start_period: 120s\n      retries: 3\n".to_string()
    };
    let example = &svc[0].0;
    let mut header = format!("# hiddenforge compose fragment (hiddenforge v{VERSION}, contract {CONTRACT_VERSION}).");
    if o.no_root {
        header += "\n# No-root mode: the container runs as the tor user (100:101) with no capabilities at all.";
    }
    let user_line = if o.no_root { "    user: \"100:101\"\n" } else { "" };
    let caps = if o.no_root {
        "    cap_drop: [ALL]\n"
    } else {
        "    cap_drop: [ALL]\n    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]\n"
    };
    let keys_mount = yaml_dq(&format!("{}:/var/lib/tor/hidden_service", o.keys));
    let (image, container) = (o.image, o.container);
    format!(
        "{header}
# Merge it into YOUR compose file; do not edit it:
#
#   {compose_cmd} -f compose.yml -f compose.service.yml up -d
#
# Your backend service must join the `tor-internal` network below and must NOT
# publish any ports. hiddenforge reaches it by service name; the resolved IP is
# pinned into the torrc at container start.
#
# Address:  hiddenforge show --json --name {example}
# Ready:    hiddenforge status --json   (poll the `ready` field)
#
# Threat model: state-level adversary. Do not weaken these flags.

networks:
  tor-internal:
    internal: true
  tor-external: {{}}

services:
  {container}:
    image: {image}
    restart: {restart}
{user_line}{caps}    security_opt:
      - no-new-privileges:true
{apparmor}    read_only: true
    pids_limit: 256
    mem_limit: 512m
    memswap_limit: 512m
    cpus: 1.0
    ulimits:
      nofile:
        soft: 8192
        hard: 8192
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m
      {etc_tmpfs}
      {tor_tmpfs}
    logging:
      driver: none
    environment:
{env_lines}    volumes:
      - {keys_mount}
    networks:
      - tor-internal
      - tor-external
    # No DNS leaves the container: backend names still resolve on the internal
    # network, but a name that does not (a backend down or not up yet) is never
    # forwarded upstream. Tor itself needs no DNS.
    dns: 127.0.0.1
{healthcheck}{dep_block}"
    )
}

fn render_deploy(services: &Services, o: &SetupOpts) -> String {
    let names: Vec<String> = sorted(services).iter().map(|(n, _)| shlex_quote(n)).collect();
    let names = names.join(" ");
    let keys_q = shlex_quote(o.keys);
    let disp = o.keys.replace('\\', "\\\\").replace('"', "'").replace('$', "\\$").replace('`', "'");
    let (engine_check, up) = if o.runtime == "podman" {
        (
            r#"COMPOSE=""
SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
for p in /usr/libexec/docker/cli-plugins/docker-compose \
         /usr/lib/docker/cli-plugins/docker-compose \
         /usr/local/lib/docker/cli-plugins/docker-compose \
         "$HOME/.docker/cli-plugins/docker-compose"; do
    if [ -x "$p" ] && [ -S "$SOCK" ]; then
        COMPOSE="$p"
        export DOCKER_HOST="unix://$SOCK"
        break
    fi
done
if [ -z "$COMPOSE" ]; then
    if command -v podman-compose >/dev/null 2>&1; then
        COMPOSE=podman-compose
        echo "note: podman-compose does not apply pids_limit (before 1.1) or" >&2
        echo "memswap_limit; Docker Compose on the Podman socket does (README)." >&2
    else
        echo "Neither Docker Compose (with podman.socket) nor podman-compose found." >&2
        exit 1
    fi
fi"#
            .to_string(),
            "\"$COMPOSE\"".to_string(),
        )
    } else {
        (
            "if ! command -v docker >/dev/null 2>&1; then\n    echo \"docker not installed. Install Docker Engine first.\" >&2\n    exit 1\nfi"
                .to_string(),
            "docker compose".to_string(),
        )
    };
    let container_q = shlex_quote(o.container);
    let own_step = if !o.no_root {
        String::new()
    } else if o.runtime == "podman" {
        format!("echo \"==> Handing the key directory to the tor user (100:101)\"\npodman unshare chown -R 100:101 {keys_q}\n")
    } else {
        format!(
            "if [ \"$(stat -c %u:%g {keys_q})\" != \"100:101\" ]; then\n    echo \"==> Handing the key directory to the tor user (100:101); sudo asks once\"\n    sudo chown -R 100:101 {keys_q}\nfi\n"
        )
    };
    let status_line = shlex_quote(&format!("  hiddenforge status --container {} --keys {keys_q}", o.container));
    let persisted = if o.runtime == "podman" {
        format!("{disp}/$svc/hostname (read it with the exec command above)")
    } else {
        format!("{disp}/$svc/hostname and {disp}/$svc.onion")
    };
    format!(
        r#"#!/usr/bin/env bash
# hiddenforge, one-shot deploy. Generated by `hiddenforge setup`.
# Usage: ./deploy.sh [path/to/your-compose.yml]
set -euo pipefail
cd "$(dirname "$0")"

BASE="${{1:-compose.yml}}"
{engine_check}

echo "==> Preparing key directory {disp}"
mkdir -p {keys_q}
chmod 700 {keys_q} 2>/dev/null || :
{own_step}
echo "==> Bringing the stack up"
{up} -f "$BASE" -f compose.service.yml up -d

echo "==> Waiting for the .onion address(es) (up to 180s each)"
for svc in {names}; do
    onion=""
    for _ in $(seq 1 180); do
        onion=$({up} -f "$BASE" -f compose.service.yml exec -T {container_q} \
            su-exec tor cat /var/lib/tor/hidden_service/$svc/hostname 2>/dev/null || true)
        if [ -n "$onion" ]; then break; fi
        sleep 1
    done
    echo
    echo "================================================================="
    if [ -n "$onion" ]; then
        echo "$svc .onion: $onion"
        echo "Persisted to: {persisted}"
    else
        echo "$svc: no address yet. Container logging is off by design; run"
        printf '%s\n' {status_line}
    fi
done
echo "The address WORKS only once 'hiddenforge status' reports ready: true (Tor"
echo "must publish it to the network first; a few minutes on a first boot)."
echo "BACK UP THE ENTIRE {disp} DIRECTORY. It IS your address."
echo "================================================================="
"#
    )
}

fn render_readme(services: &Services, o: &SetupOpts) -> String {
    let svc = sorted(services);
    let block: Vec<String> = svc.iter().map(|(n, v)| format!("  {n}: {}=\"{}\"", env_var(n), v.join(","))).collect();
    let block = block.join("\n");
    let names: Vec<&str> = svc.iter().map(|(n, _)| n.as_str()).collect();
    let names = names.join(", ");
    let compose_cmd = if o.runtime == "podman" { "podman-compose" } else { "docker compose" };
    let keys_q = shlex_quote(o.keys);
    let (image, keys) = (o.image, o.keys);
    format!(
        "hiddenforge, your setup
=========================

Services:
{block}
Image:     {image}
Keys:      {keys}

How to bring it up
------------------
1. Make sure every backend service joins the `tor-internal` network and has no
   published ports.
2. ./deploy.sh   (or: {compose_cmd} -f compose.yml -f compose.service.yml up -d)

Where the addresses live
------------------------
  {keys}/<service>/hostname   <- Tor's own hostname file
  {keys}/<service>.onion      <- world-readable copy written at startup

Read one any time:
  hiddenforge show --keys {keys_q} --name <service> --json

Services: {names}

BACK UP THE ENTIRE {keys} DIRECTORY. A key IS a .onion address.
Losing it loses that address permanently.

If a backend is recreated on a different IP, hiddenforge notices and restarts
itself to follow it (this needs the restart policy the fragment sets).
"
    )
}

fn random_hex8() -> String {
    let mut b = [0u8; 8];
    // SAFETY: getrandom into a stack buffer.
    unsafe { libc::getrandom(b.as_mut_ptr().cast(), 8, 0) };
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// _write_bytes_nofollow: new O_EXCL temp beside the target, fchmod, fsync, rename.
fn write_bytes_nofollow(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    match fsops::lstat(path) {
        Ok(st) if !fsops::is_type(&st, libc::S_IFREG) => {
            return Err(format!("[Errno 17] refusing to replace {path}: it is not a regular file"))
        }
        _ => {}
    }
    let (dir, base) = path.rsplit_once('/').unwrap_or((".", path));
    let tmp = format!("{dir}/.{base}.{}.tmp", random_hex8());
    let r = (|| -> Result<(), String> {
        let fd = fsops::open(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, mode).map_err(|e| e.msg)?;
        let mut off = 0;
        while off < data.len() {
            // SAFETY: writing from a live slice.
            let n = unsafe { libc::write(fd.0, data[off..].as_ptr().cast(), data.len() - off) };
            if n < 0 {
                return Err(py::oserror(py::last_errno()));
            }
            off += n as usize;
        }
        fsops::fchmod(&fd, mode).map_err(|e| e.msg)?;
        // SAFETY: fd is open.
        unsafe { libc::fsync(fd.0) };
        drop(fd);
        std::fs::rename(&tmp, path).map_err(|e| py::oserror(e.raw_os_error().unwrap_or(0)))
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

fn realpath_lenient(p: &str) -> String {
    let abs = if p.starts_with('/') {
        py_path(p)
    } else {
        let cwd = std::env::current_dir().map(|c| c.to_string_lossy().into_owned()).unwrap_or_else(|_| "/".into());
        py_path(&format!("{cwd}/{p}"))
    };
    std::fs::canonicalize(&abs).map(|c| c.to_string_lossy().into_owned()).unwrap_or(abs)
}

fn cmd_setup(a: &Args) -> i32 {
    let r = (|| -> Result<i32, (i32, String)> {
        let usage = |e: String| (EXIT_USAGE, e);
        let mut services: Services = Vec::new();
        fn add(services: &mut Services, n: String, m: String) {
            match services.iter_mut().find(|(k, _)| *k == n) {
                Some((_, v)) => {
                    if !v.contains(&m) {
                        v.push(m);
                    }
                }
                None => services.push((n, vec![m])),
            }
        }
        for spec in a.get("services").unwrap_or("").split(',') {
            if !py::strip_str(spec).is_empty() {
                let (n, m) = parse_service_spec(py::strip_str(spec)).map_err(usage)?;
                add(&mut services, n, m);
            }
        }
        for spec in a.list("service").cloned().unwrap_or_default() {
            let (n, m) = parse_service_spec(&spec).map_err(usage)?;
            add(&mut services, n, m);
        }
        let onion_port = int_arg(a, "onion_port", 80);
        let name = a.get("name").unwrap_or(DEFAULT_NAME).to_string();
        if let Some(b) = a.get("backend") {
            let (h, p) = parse_backend(b).map_err(usage)?;
            add(&mut services, validate_name(&name).map_err(usage)?, format!("{onion_port}:{h}:{p}"));
        }
        if services.is_empty() {
            if a.flag("non_interactive") || a.flag("json") || !stdin_tty() {
                return Err(usage("--backend service:port is required (or --service/--services)".into()));
            }
            eprint!("Backend service:port (e.g. web:80): ");
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 || py::strip_str(&line).is_empty() {
                return Err((EXIT_ABORTED, "aborted at prompt".into()));
            }
            let (h, p) = parse_backend(py::strip_str(&line)).map_err(usage)?;
            add(&mut services, validate_name(&name).map_err(usage)?, format!("{onion_port}:{h}:{p}"));
        }
        let out = py_path(a.get("out").unwrap_or("./hiddenforge-deploy"));
        std::fs::create_dir_all(&out).map_err(|e| (EXIT_FAIL, py::oserror_path(e.raw_os_error().unwrap_or(0), &out)))?;
        let outputs = ["compose.service.yml", "deploy.sh", "README.txt", "hiddenforge.json"];
        let existing: Vec<&str> = outputs.iter().copied().filter(|p| fsops::lstat(&join(&out, p)).is_ok()).collect();
        if !existing.is_empty() && !a.flag("force") {
            return Err(usage(format!("{out} already contains {}; pass --force to overwrite", existing.join(", "))));
        }
        let odd: Vec<&str> = existing
            .iter()
            .copied()
            .filter(|p| fsops::lstat(&join(&out, p)).is_ok_and(|s| !fsops::is_type(&s, libc::S_IFREG)))
            .collect();
        if !odd.is_empty() {
            return Err(usage(format!(
                "refusing to replace {} in {out}: not a regular file (a symlink, directory or FIFO is not something setup wrote)",
                odd.join(", ")
            )));
        }
        let image = validate_image_ref(&a.get("image").map_or_else(default_image, String::from)).map_err(usage)?;
        let keys = validate_keys_dir(a.get("keys").unwrap_or(DEFAULT_KEYS)).map_err(usage)?;
        let container = validate_container(a.get("container").unwrap_or(DEFAULT_CONTAINER)).map_err(usage)?;
        let runtime = a.get("runtime").unwrap_or("docker").to_string();
        if !(1..=65535).contains(&onion_port) {
            return Err(usage(format!(
                "--onion-port must be 1-65535, got {onion_port}. Emitting it anyway would write a compose file whose service the container drops at boot, with the reason only in the container log."
            )));
        }
        let no_root = a.flag("no_root");
        let o = SetupOpts { image: &image, keys: &keys, container: &container, runtime: &runtime, no_root };
        let fail = |e: String| (EXIT_FAIL, e);
        write_bytes_nofollow(&join(&out, "compose.service.yml"), render_compose(&services, &o).as_bytes(), 0o644).map_err(fail)?;
        write_bytes_nofollow(&join(&out, "deploy.sh"), render_deploy(&services, &o).as_bytes(), 0o755).map_err(fail)?;
        write_bytes_nofollow(&join(&out, "README.txt"), render_readme(&services, &o).as_bytes(), 0o644).map_err(fail)?;
        let compose_cmd = if runtime == "podman" { "podman-compose" } else { "docker compose" };
        let merge = format!("{compose_cmd} -f compose.yml -f {} up -d", shlex_quote(&format!("{out}/compose.service.yml")));
        let svc = sorted(&services);
        let svc_list: Vec<Json> = svc
            .iter()
            .map(|(n, v)| {
                Json::obj()
                    .with("name", n.as_str().into())
                    .with("env_var", env_var(n).into())
                    .with("env_value", v.join(",").into())
                    .with("address_command", format!("hiddenforge show --json --name {n}").into())
                    .with("address_file", format!("{keys}/{n}.onion").into())
                    .with("key_path", format!("{keys}/{n}/{SECRET_FILE}").into())
            })
            .collect();
        let (first, firstmaps) = (&svc[0].0, &svc[0].1);
        let descriptor = Json::obj()
            .with("name", first.as_str().into())
            .with("env_var", env_var(first).into())
            .with("env_value", firstmaps.join(",").into())
            .with("services", Json::Arr(svc_list))
            .with("backend", firstmaps[0].split(':').nth(1).unwrap_or("").into())
            .with("image", image.as_str().into())
            .with("keys", keys.as_str().into())
            .with("container", container.as_str().into())
            .with("runtime", runtime.as_str().into())
            .with("onion_port", Json::Int(onion_port))
            .with("output_dir", realpath_lenient(&out).into())
            .with("merge", merge.as_str().into())
            .with("address_command", format!("hiddenforge show --json --name {first}").into())
            .with("ready_command", "hiddenforge status --json".into())
            .with("bare_command", merge.as_str().into())
            .with("address_file", format!("{keys}/{first}.onion").into())
            .with("key_path", format!("{keys}/{first}/{SECRET_FILE}").into())
            .with("contract_version", Json::Int(CONTRACT_VERSION))
            .with("hiddenforge_version", VERSION.into());
        let mut descriptor = descriptor;
        if no_root {
            descriptor.set("no_root", true.into());
        }
        write_bytes_nofollow(&join(&out, "hiddenforge.json"), (py::dumps(&descriptor, true, Some(2)) + "\n").as_bytes(), 0o644)
            .map_err(fail)?;
        if a.flag("json") {
            let mut doc = Json::obj().with("ok", true.into()).with("exit_code", Json::Int(0));
            if let Json::Obj(items) = descriptor {
                for (k, v) in items {
                    doc.set(&k, v);
                }
            }
            println!("{}", py::dumps(&doc, true, Some(2)));
            return Ok(EXIT_OK);
        }
        for f in outputs {
            println!("Wrote {out}/{f}");
        }
        println!();
        println!("Next:");
        println!("  1. Put each backend on the `tor-internal` network, with no ports.");
        println!("  2. {merge}");
        for (n, _) in &svc {
            println!("  3. hiddenforge show --json --name {n}");
        }
        Ok(EXIT_OK)
    })();
    match r {
        Ok(rc) => rc,
        Err((code, e)) => emit_json(code, vec![("error", e.into())]),
    }
}

// ── rotate ──

fn ismount(p: &str) -> bool {
    let Ok(st) = fsops::lstat(p) else { return false };
    if fsops::is_type(&st, libc::S_IFLNK) {
        return false;
    }
    let parent = format!("{}/..", py_path(p));
    let Ok(ps) = fsops::lstat(&parent) else { return false };
    st.st_dev != ps.st_dev || st.st_ino == ps.st_ino
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rotate_inside(keys: &str) -> Result<(String, Vec<String>), (i32, String)> {
    let _root = fsops::open_dir_nofollow(keys).map_err(|e| (EXIT_FAIL, e.msg))?;
    let mut entries: Vec<String> = std::fs::read_dir(keys)
        .map_err(|e| (EXIT_FAIL, py::oserror(e.raw_os_error().unwrap_or(0))))?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| !n.starts_with(".rotated-"))
        .collect();
    entries.sort();
    if entries.is_empty() {
        return Err((EXIT_USAGE, format!("{keys} holds no identity to rotate")));
    }
    let stuck: Vec<&String> = entries
        .iter()
        .filter(|n| {
            let p = join(keys, n);
            fsops::lstat(&p).is_ok_and(|s| fsops::is_type(&s, libc::S_IFDIR)) && !access(&p, libc::W_OK)
        })
        .collect();
    if !stuck.is_empty() {
        let s: Vec<&str> = stuck.iter().map(|s| s.as_str()).collect();
        return Err((
            EXIT_FAIL,
            format!(
                "[Errno 13] cannot move {} (not writable by this user); nothing was rotated. Run rotate where the service directories are writable, e.g. inside the container",
                s.join(", ")
            ),
        ));
    }
    let base = format!(".rotated-{}", now_secs());
    let (mut name, mut n) = (base.clone(), 1);
    loop {
        let c = CString::new(join(keys, &name)).unwrap_or_default();
        // SAFETY: valid C string.
        if unsafe { libc::mkdir(c.as_ptr(), 0o700) } == 0 {
            break;
        }
        if py::last_errno() != libc::EEXIST {
            return Err((EXIT_FAIL, py::oserror(py::last_errno())));
        }
        name = format!("{base}-{n}");
        n += 1;
    }
    let archive = join(keys, &name);
    if crate::privs::is_root() {
        if let (Ok(vol), Ok(arc)) = (fsops::lstat(keys), fsops::lstat(&archive)) {
            if arc.st_uid != vol.st_uid {
                let c = CString::new(archive.clone()).unwrap_or_default();
                // SAFETY: valid C string; lchown never follows.
                unsafe { libc::lchown(c.as_ptr(), vol.st_uid, vol.st_gid) };
            }
        }
    }
    for e in &entries {
        std::fs::rename(join(keys, e), join(&archive, e)).map_err(|er| (EXIT_FAIL, py::oserror(er.raw_os_error().unwrap_or(0))))?;
    }
    Ok((archive, entries))
}

fn cmd_rotate(a: &Args) -> i32 {
    let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
    if !is_dir(&keys) {
        return emit_json(EXIT_USAGE, vec![("keys", keys.as_str().into()), ("error", format!("key directory {keys} does not exist").into())]);
    }
    if py::strip_str(a.get("confirm").unwrap_or("")) != "ROTATE" {
        return emit_json(
            EXIT_USAGE,
            vec![("keys", keys.as_str().into()), ("error", "refusing to destroy an identity without --confirm ROTATE".into())],
        );
    }
    let res = if ismount(&keys) {
        rotate_inside(&keys).map(|(a, m)| (a, Some(m)))
    } else {
        if !access(&keys, libc::W_OK) {
            return emit_json(EXIT_FAIL, vec![("keys", keys.as_str().into()), ("error", "key directory is not writable".into())]);
        }
        let mut cand = format!("{keys}.rotated-{}", now_secs());
        let mut n = 1;
        while fsops::lstat(&cand).is_ok() {
            cand = format!("{keys}.rotated-{}-{n}", now_secs());
            n += 1;
        }
        std::fs::rename(&keys, &cand)
            .and_then(|()| {
                std::fs::create_dir(&keys)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            })
            .map(|()| (cand, None))
            .map_err(|e| (EXIT_FAIL, py::oserror(e.raw_os_error().unwrap_or(0))))
    };
    match res {
        Err((EXIT_USAGE, e)) => emit_json(EXIT_USAGE, vec![("keys", keys.as_str().into()), ("error", e.into())]),
        Err((code, e)) => emit_json(code, vec![("error", e.into())]),
        Ok((archived, moved)) => {
            let note = "A running container keeps serving the old address from memory until it is restarted; restart it to generate the new one.";
            if a.flag("json") {
                let moved = moved.map_or(Json::Null, |m| Json::Arr(m.into_iter().map(Json::Str).collect()));
                return emit_json(
                    EXIT_OK,
                    vec![("keys", keys.as_str().into()), ("archived", archived.into()), ("moved", moved), ("note", note.into())],
                );
            }
            println!("Moved the old identity to {archived}");
            println!("{keys} is empty of identities now. {note}");
            EXIT_OK
        }
    }
}

// ── backup / restore / encrypt-key / decrypt-key (no crypto tools in the image) ──

fn pick_tool(preferred: Option<&str>, suffix: &str, non_interactive: bool) -> Option<String> {
    if let Some(p) = preferred {
        return Some(p.into());
    }
    if suffix.ends_with(".age") && which("age") {
        return Some("age".into());
    }
    if suffix.ends_with(".gpg") && which("gpg") {
        return Some("gpg".into());
    }
    if non_interactive {
        if which("gpg") {
            return Some("gpg".into());
        }
        return which("age").then(|| "age".into());
    }
    ["age", "gpg"].iter().find(|t| which(t)).map(|t| t.to_string())
}

fn passphrase_check(a: &Args, tool: &str) -> Result<(), String> {
    if let Some(p) = a.get("passphrase_file") {
        let d = std::fs::read(p).map_err(|e| py::oserror_path(e.raw_os_error().unwrap_or(0), p))?;
        if d.len() > 4096 {
            return Err("passphrase file too large".into());
        }
        return Ok(());
    }
    if !stdin_tty() {
        if tool == "age" {
            return Err("age prompts for its passphrase on a TTY and cannot run unattended; use --tool gpg with --passphrase-file instead".into());
        }
        return Err("no passphrase source: pass --passphrase-file (or a TTY)".into());
    }
    Ok(())
}

fn tool_missing(tool: &str) -> String {
    format!("{tool}: [Errno 2] No such file or directory: {}. {}", py::py_repr(tool), no_tool_error())
}

fn cmd_backup(a: &Args) -> i32 {
    let r = (|| -> Result<i32, String> {
        let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
        if !is_dir(&keys) {
            return Err(format!("key directory {keys} does not exist"));
        }
        let ni = a.get("passphrase_file").is_some() || !stdin_tty();
        let tool = pick_tool(a.get("tool"), a.get("out").unwrap_or(""), ni).ok_or_else(no_tool_error)?;
        if tool == "openssl" {
            return Err("openssl is refused for backup creation (no authentication)".into());
        }
        passphrase_check(a, &tool)?;
        Err(tool_missing(&tool))
    })();
    r.unwrap_or_else(|e| emit_json(EXIT_USAGE, vec![("error", e.into())]))
}

fn cmd_restore(a: &Args) -> i32 {
    let r = (|| -> Result<i32, String> {
        let src = a.get("input").unwrap_or("");
        if !std::fs::metadata(src).is_ok_and(|m| m.is_file()) {
            return Err(format!("backup {} does not exist", py_path(src)));
        }
        let tool = a
            .get("tool")
            .map(String::from)
            .or_else(|| {
                if src.ends_with(".age") {
                    Some("age".into())
                } else if src.ends_with(".gpg") {
                    Some("gpg".into())
                } else {
                    None
                }
            })
            .ok_or("cannot infer --tool from the input name; pass --tool")?;
        passphrase_check(a, &tool)?;
        Err(tool_missing(&tool))
    })();
    r.unwrap_or_else(|e| emit_json(EXIT_USAGE, vec![("error", e.into())]))
}

fn cmd_crypt(a: &Args) -> i32 {
    let r = (|| -> Result<i32, String> {
        validate_name(a.get("name").unwrap_or(""))?;
        let ni = a.get("passphrase_file").is_some() || !stdin_tty();
        let tool = pick_tool(a.get("tool"), "", ni).ok_or_else(no_tool_error)?;
        if tool == "openssl" {
            return Err("openssl is refused (no authentication)".into());
        }
        passphrase_check(a, &tool)?;
        Err(tool_missing(&tool))
    })();
    r.unwrap_or_else(|e| emit_json(EXIT_USAGE, vec![("error", e.into())]))
}

// ── vanity (vanity.py) ──

fn emit_vanity(rc: i32, json: bool, payload: Vec<(&str, Json)>, human: &str) -> i32 {
    if json {
        let mut doc = Json::obj().with("ok", (rc == 0).into()).with("exit_code", Json::Int(i64::from(rc)));
        for (k, v) in payload {
            if v != Json::Null {
                doc.set(k, v);
            }
        }
        println!("{}", py::dumps(&doc, true, None));
    } else if !human.is_empty() {
        println!("{human}");
    }
    rc
}

fn mkp224o_path() -> Result<String, String> {
    let env = std::env::var("MKP224O").ok();
    for c in [env.as_deref(), Some("/usr/local/bin/mkp224o"), Some("/usr/bin/mkp224o")].into_iter().flatten() {
        if std::fs::metadata(c).is_ok_and(|m| m.is_file()) && access(c, libc::X_OK) {
            return Ok(c.into());
        }
    }
    Err("mkp224o not found. This subcommand requires the hiddenforge image (which vendors it); run it via `hiddenforge vanity` on the host.".into())
}

fn human_duration(s: f64) -> String {
    if s < 1.0 {
        "<1s".into()
    } else if s < 60.0 {
        format!("{s:.0}s")
    } else if s < 3600.0 {
        format!("{:.1}m", s / 60.0)
    } else if s < 86400.0 {
        format!("{:.1}h", s / 3600.0)
    } else if s < 86400.0 * 365.0 {
        format!("{:.1}d", s / 86400.0)
    } else {
        format!("{:.1}y", s / (86400.0 * 365.0))
    }
}

fn benchmark(seconds: i64, threads: i64) -> Result<f64, String> {
    use std::io::BufRead;
    let seconds = seconds.max(1);
    let tmp = format!("/tmp/hf-bench-{}", random_hex8());
    std::fs::create_dir(&tmp).map_err(|e| e.to_string())?;
    let mut child = std::process::Command::new(mkp224o_path()?)
        .args(["-d", &tmp, "-t", &threads.to_string(), "-n", "0", "-S", "1", "-T", "zzzzzzzzzz"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut best = 0.0f64;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds as u64);
    if let Some(err) = child.stderr.take() {
        let mut rd = std::io::BufReader::new(err);
        let mut line = String::new();
        while std::time::Instant::now() < deadline {
            line.clear();
            if rd.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(i) = line.find("calc/sec:") {
                let v: String = line[i + 9..].trim_start().chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
                if let Ok(r) = v.parse::<f64>() {
                    best = r;
                }
            }
        }
    }
    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
    if best <= 0.0 {
        return Err("mkp224o produced no statistics; cannot benchmark".into());
    }
    Ok(best)
}

fn vanity_generate(prefix: &str, name: &str, out: &str, threads: i64, force: bool, uid: Option<u32>, gid: Option<u32>) -> Result<Json, (i32, String)> {
    let target = join(out, name);
    let exists = fsops::lstat(&target).is_ok();
    if exists && !force {
        return Err((EXIT_USAGE, format!(
            "{target} already exists. Refusing to overwrite a key set: the key IS the .onion address and there is no recovery. Pass --force to archive the old one and generate a fresh address."
        )));
    }
    std::fs::create_dir_all(out).map_err(|e| (EXIT_FAIL, e.to_string()))?;
    let tmp = join(out, &format!("hf-vanity-{}", random_hex8()));
    std::fs::create_dir(&tmp).map_err(|e| (EXIT_FAIL, e.to_string()))?;
    let res = (|| -> Result<(String, Option<String>), (i32, String)> {
        let outp = std::process::Command::new(mkp224o_path().map_err(|e| (EXIT_FAIL, e))?)
            .args(["-d", &tmp, "-t", &threads.to_string(), "-n", "1", prefix])
            .stdout(std::process::Stdio::null())
            .output()
            .map_err(|e| (EXIT_FAIL, e.to_string()))?;
        let generated: Vec<String> = std::fs::read_dir(&tmp)
            .map_err(|e| (EXIT_FAIL, e.to_string()))?
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.ends_with(".onion"))
            .collect();
        if !outp.status.success() && generated.is_empty() {
            let err = String::from_utf8_lossy(&outp.stderr);
            let err = err.trim();
            let tail: String = err.chars().rev().take(500).collect::<Vec<_>>().into_iter().rev().collect();
            return Err((EXIT_FAIL, format!("mkp224o exited {}: {tail}", outp.status.code().unwrap_or(-1))));
        }
        if generated.len() != 1 {
            return Err((EXIT_FAIL, format!("expected exactly one generated .onion directory, found {}", generated.len())));
        }
        let dir_onion = generated[0].clone();
        let src = join(&tmp, &dir_onion);
        if !fsops::is_onion(&dir_onion) {
            return Err((EXIT_FAIL, format!("generator produced an invalid address name: {}", py::py_repr(&dir_onion))));
        }
        if !dir_onion.starts_with(prefix) {
            return Err((EXIT_FAIL, format!("generated address {dir_onion} does not start with prefix {}", py::py_repr(prefix))));
        }
        let file_onion = std::fs::read(join(&src, HOSTNAME_FILE))
            .ok()
            .filter(|d| d.is_ascii())
            .map(|d| py::strip_str(&String::from_utf8_lossy(&d)).to_string())
            .filter(|t| fsops::is_onion(t));
        if file_onion.as_deref() != Some(dir_onion.as_str()) {
            return Err((EXIT_FAIL, format!(
                "hostname file ({}) disagrees with directory name ({})",
                file_onion.map_or("None".into(), |f| py::py_repr(&f)),
                py::py_repr(&dir_onion)
            )));
        }
        let pk = std::fs::read(join(&src, PUBLIC_FILE)).map_err(|e| (EXIT_FAIL, e.to_string()))?;
        let pk = if pk.len() == 64 && pk.starts_with(PUBLIC_TAG) { pk[32..].to_vec() } else { pk };
        let derived = sha3::derive_onion(&pk).ok_or((EXIT_FAIL, format!(
            "{PUBLIC_FILE}: expected 64 bytes (tagged) or 32 bytes (bare), got {}",
            pk.len()
        )))?;
        if derived != dir_onion {
            return Err((EXIT_FAIL, format!("address derived from public key ({derived}) disagrees with the generated address ({dir_onion})")));
        }
        let mut archived = None;
        if fsops::lstat(&target).is_ok() && force {
            let base = join(out, &format!("{name}.replaced-{}", now_secs()));
            let (mut cand, mut n) = (base.clone(), 1);
            while fsops::lstat(&cand).is_ok() {
                cand = format!("{base}-{n}");
                n += 1;
            }
            std::fs::rename(&target, &cand).map_err(|e| (EXIT_FAIL, e.to_string()))?;
            let _ = std::fs::remove_file(join(out, &format!("{name}.onion")));
            archived = Some(cand);
        }
        if let Err(e) = std::fs::rename(&src, &target) {
            if fsops::lstat(&target).is_ok() {
                return Err((EXIT_RACE, format!("{target} appeared while the search was running; refusing to clobber it (exit 3)")));
            }
            return Err((EXIT_FAIL, e.to_string()));
        }
        Ok((dir_onion, archived))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    let (onion, archived) = res?;
    harden(&target, uid, gid).map_err(|e| (EXIT_FAIL, e))?;
    Ok(Json::obj()
        .with("name", name.into())
        .with("onion", onion.into())
        .with("key_path", format!("{target}/{SECRET_FILE}").into())
        .with("public_key_path", format!("{target}/{PUBLIC_FILE}").into())
        .with("address_path", format!("{target}/{HOSTNAME_FILE}").into())
        .with("key_dir", target.as_str().into())
        .with("archived", archived.into())
        .with("threads", Json::Int(threads)))
}

fn harden(dir: &str, uid: Option<u32>, gid: Option<u32>) -> Result<(), String> {
    let (u, g) = (uid.unwrap_or(u32::MAX), gid.unwrap_or(u32::MAX));
    let chown = uid.is_some() || gid.is_some();
    let dfd = fsops::open_dir_nofollow(dir).map_err(|e| e.msg)?;
    let mut names: Vec<String> = std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten().filter_map(|e| e.file_name().to_str().map(String::from)).collect();
    names.sort();
    for n in names {
        let Ok(fd) = fsops::open(&join(dir, &n), libc::O_RDONLY | libc::O_NOFOLLOW, 0) else { continue };
        fsops::fchmod(&fd, if n == HOSTNAME_FILE { 0o644 } else { 0o600 }).map_err(|e| e.msg)?;
        if chown {
            // SAFETY: fd open; -1 (u32::MAX) leaves that id unchanged.
            unsafe { libc::fchown(fd.0, u, g) };
        }
    }
    fsops::fchmod(&dfd, 0o700).map_err(|e| e.msg)?;
    if chown {
        // SAFETY: as above.
        unsafe { libc::fchown(dfd.0, u, g) };
    }
    Ok(())
}

fn cmd_vanity(argv: &[String]) -> i32 {
    let specs = [
        Opt { required: true, ..o("--prefix", Kind::Value) },
        o("--name", Kind::Value),
        o("--out", Kind::Value),
        Opt { int: true, ..o("--threads", Kind::Value) },
        o("--force", Kind::Flag),
        Opt { int: true, ..o("--uid", Kind::Value) },
        Opt { int: true, ..o("--gid", Kind::Value) },
        o("--bench", Kind::Flag),
        Opt { int: true, ..o("--seconds", Kind::Value) },
        o("--json", Kind::Flag),
    ];
    let a = match parse("vanity.py", &specs, argv) {
        Ok(a) => a,
        Err(rc) => return rc,
    };
    let json = a.flag("json");
    let prefix = a.get("prefix").unwrap_or("");
    let name = a.get("name").unwrap_or(DEFAULT_NAME);
    if !(1..=12).contains(&prefix.len()) || !prefix.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        let r = py::py_repr(prefix);
        return emit_vanity(EXIT_USAGE, json, vec![("error", format!("invalid prefix {r}: use base32 characters a-z and 2-7 (no 0,1,8,9), max 12").into())], &format!("error: invalid prefix {r}"));
    }
    if !name_ok(name) {
        let r = py::py_repr(name);
        return emit_vanity(EXIT_USAGE, json, vec![("error", format!("invalid name {r}").into())], &format!("error: invalid name {r}"));
    }
    let threads = match int_arg(&a, "threads", 0) {
        t if t > 0 => t,
        _ => std::thread::available_parallelism().map_or(1, |n| n.get() as i64),
    }
    .clamp(1, 256);
    let seconds = int_arg(&a, "seconds", 5);
    let rate = match benchmark(seconds, threads) {
        Ok(r) => r,
        Err(e) => return emit_vanity(EXIT_USAGE, json, vec![("error", format!("benchmark failed: {e}").into())], &format!("error: benchmark failed: {e}")),
    };
    let rows: Vec<(i64, i64, f64)> = (1..=8).map(|l: u32| (i64::from(l), 32i64.pow(l), 32f64.powi(l as i32) / rate)).collect();
    if a.flag("bench") {
        let table = Json::Arr(
            rows.iter()
                .map(|(l, at, s)| {
                    Json::obj()
                        .with("prefix_len", Json::Int(*l))
                        .with("average_attempts", Json::Int(*at))
                        .with("estimated_seconds", Json::Float(*s))
                        .with("estimated_human", human_duration(*s).into())
                })
                .collect(),
        );
        let payload = vec![
            ("prefix", prefix.into()),
            ("threads", Json::Int(threads)),
            ("seconds", Json::Int(seconds)),
            ("keys_per_sec", Json::Float(py::py_round(rate, 2))),
            ("keys_per_sec_per_thread", Json::Float(py::py_round(rate / threads as f64, 2))),
            ("difficulty", table),
        ];
        if json {
            return emit_vanity(EXIT_OK, true, payload, "");
        }
        let commas = |x: f64| {
            let s = format!("{:.0}", x);
            let (neg, d) = s.strip_prefix('-').map_or((false, s.as_str()), |r| (true, r));
            let mut out = String::new();
            for (i, ch) in d.chars().enumerate() {
                if i > 0 && (d.len() - i) % 3 == 0 {
                    out.push(',');
                }
                out.push(ch);
            }
            if neg { format!("-{out}") } else { out }
        };
        let mut lines = vec![
            format!("mkp224o throughput: {} keys/sec ({threads} threads, {} keys/sec/thread)", commas(rate), commas(rate / threads as f64)),
            String::new(),
            "prefix len   average attempts        expected time".into(),
        ];
        for (l, at, s) in &rows {
            lines.push(format!("{l:>9}   {:>18}   {:>13}", commas(*at as f64), human_duration(*s)));
        }
        return emit_vanity(EXIT_OK, false, payload, &lines.join("\n"));
    }
    let est = 32f64.powi(prefix.len() as i32) / rate;
    if est > 86400.0 && !json {
        eprintln!(
            "warning: a {}-character prefix needs ~{} on this machine. Consider a shorter prefix or a faster host (see docs/INTEGRATION.md, 'Long prefixes').",
            prefix.len(),
            human_duration(est)
        );
    }
    let out = a.get("out").map_or_else(|| std::env::var("HIDDENFORGE_KEYS_DIR").unwrap_or_else(|_| "/var/lib/tor/hidden_service".into()), String::from);
    let uid = a.get("uid").and_then(|v| v.trim().parse().ok());
    let gid = a.get("gid").and_then(|v| v.trim().parse().ok());
    match vanity_generate(prefix, name, &py_path(&out), threads, a.flag("force"), uid, gid) {
        Err((code, e)) => emit_vanity(code, json, vec![("error", e.clone().into()), ("name", name.into())], &format!("error: {e}")),
        Ok(mut r) => {
            let onion = match r.get("onion") {
                Some(Json::Str(s)) => s.clone(),
                _ => String::new(),
            };
            r.set("address_matches_prefix", onion.starts_with(prefix).into());
            let s = |k| match r.get(k) {
                Some(Json::Str(s)) => s.clone(),
                _ => String::new(),
            };
            let human = format!(
                "Found {onion}\nWrote {} (secret, mode 0600)\nBack up {} - losing it loses the address permanently.",
                s("key_path"),
                s("key_dir")
            );
            let Json::Obj(items) = r else { return EXIT_FAIL };
            let payload: Vec<(&str, Json)> = items.into_iter().map(|(k, v)| (leak(k), v)).collect();
            emit_vanity(EXIT_OK, json, payload, &human)
        }
    }
}

// ───────────────────────────── dispatch ─────────────────────────────────────

/// Commands this binary answers (in the image). Returns None if `cmd` is not one.
pub fn run(cmd: &str, rest: &[String]) -> Option<i32> {
    let json = o("--json", Kind::Flag);
    let keys = o("--keys", Kind::Value);
    let rc = match cmd {
        "version" => parse("hiddenforge version", &[json], rest).map_or_else(|c| c, |a| cmd_version(&a)),
        "info" => parse("hiddenforge info", &[json], rest).map_or_else(|c| c, |a| cmd_info(&a)),
        "show" => parse("hiddenforge show", &[keys, o("--name", Kind::Value), o("--container", Kind::Value), json], rest)
            .map_or_else(|c| c, |a| cmd_show(&a)),
        "doctor" => parse("hiddenforge doctor", &[o("--container", Kind::Value), keys, o("--keys-only", Kind::Flag), json], rest)
            .map_or_else(|c| c, |a| cmd_doctor(&a)),
        "setup" => parse(
            "hiddenforge setup",
            &[
                Opt { short: Some("-o"), ..o("--out", Kind::Value) },
                o("--name", Kind::Value),
                o("--backend", Kind::Value),
                Opt { int: true, ..o("--onion-port", Kind::Value) },
                o("--service", Kind::Append),
                o("--services", Kind::Value),
                o("--image", Kind::Value),
                keys,
                o("--container", Kind::Value),
                Opt { choices: &["docker", "podman"], ..o("--runtime", Kind::Value) },
                o("--no-root", Kind::Flag),
                o("--force", Kind::Flag),
                o("--non-interactive", Kind::Flag),
                json,
            ],
            rest,
        )
        .map_or_else(|c| c, |a| cmd_setup(&a)),
        "rotate" => parse("hiddenforge rotate", &[keys, o("--confirm", Kind::Value), json], rest).map_or_else(|c| c, |a| cmd_rotate(&a)),
        "backup" => parse(
            "hiddenforge backup",
            &[
                keys,
                Opt { required: true, ..o("--out", Kind::Value) },
                Opt { choices: &["age", "gpg", "openssl"], ..o("--tool", Kind::Value) },
                o("--passphrase-file", Kind::Value),
                o("--require-aead", Kind::Flag),
                json,
            ],
            rest,
        )
        .map_or_else(|c| c, |a| cmd_backup(&a)),
        "restore" => parse(
            "hiddenforge restore",
            &[
                keys,
                Opt { required: true, ..o("--input", Kind::Value) },
                Opt { choices: &["age", "gpg", "openssl"], ..o("--tool", Kind::Value) },
                o("--passphrase-file", Kind::Value),
                o("--force", Kind::Flag),
                json,
            ],
            rest,
        )
        .map_or_else(|c| c, |a| cmd_restore(&a)),
        "encrypt-key" | "decrypt-key" => parse(
            &format!("hiddenforge {cmd}"),
            &[
                keys,
                Opt { required: true, ..o("--name", Kind::Value) },
                Opt { choices: &["age", "gpg"], ..o("--tool", Kind::Value) },
                o("--passphrase-file", Kind::Value),
                o("--delete-plaintext", Kind::Flag),
                o("--force", Kind::Flag),
                o("--require-aead", Kind::Flag),
                json,
            ],
            rest,
        )
        .map_or_else(|c| c, |a| cmd_crypt(&a)),
        "vanity" => cmd_vanity(rest),
        "status" | "verify-image" | "sbom" => emit_json(
            EXIT_USAGE,
            vec![("error", format!("`hiddenforge {cmd}` runs on the HOST (it needs the container engine or the registry), not inside the image").into())],
        ),
        _ => return None,
    };
    Some(rc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathlib_normalisation() {
        assert_eq!(py_path("./tor-keys"), "tor-keys");
        assert_eq!(py_path("/var//lib/./tor/"), "/var/lib/tor");
        assert_eq!(py_path("//x"), "//x");
        assert_eq!(py_path(""), ".");
        assert_eq!(join("./k", "a"), "k/a");
    }

    #[test]
    fn shlex_like_python() {
        assert_eq!(shlex_quote("./tor-keys"), "./tor-keys");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shlex_quote(""), "''");
    }

    #[test]
    fn yaml_quoting() {
        assert_eq!(yaml_dq("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(yaml_dq("é📁"), "\"\\u00e9\\U0001f4c1\"");
    }

    #[test]
    fn parses_abbreviations_and_equals() {
        let specs = [o("--name", Kind::Value), o("--json", Kind::Flag)];
        let a = parse("t", &specs, &["--na=x".into(), "--js".into()]).unwrap();
        assert_eq!(a.get("name"), Some("x"));
        assert!(a.flag("json"));
    }
}
