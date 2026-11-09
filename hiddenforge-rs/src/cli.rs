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
    std::env::var("HIDDENFORGE_IMAGE")
        .unwrap_or_else(|_| "sambent.dev/sam/hiddenforge:latest".into())
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
    Opt {
        long,
        short: None,
        kind,
        required: false,
        choices: &[],
        int: false,
    }
}

#[derive(Default, Debug)]
pub struct Args {
    vals: Vec<(String, String)>,
    flags: Vec<String>,
    appends: Vec<(String, Vec<String>)>,
}

impl Args {
    fn get(&self, k: &str) -> Option<&str> {
        self.vals
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
    fn list(&self, k: &str) -> Option<&Vec<String>> {
        self.appends.iter().find(|(n, _)| n == k).map(|(_, v)| v)
    }
}

/// How argparse names an option in an error: every spelling, `-o/--out`.
fn arg_label(s: &Opt) -> String {
    match s.short {
        Some(short) => format!("{short}/{}", s.long),
        None => s.long.to_string(),
    }
}

/// argparse's `^-\d+$|^-\d*\.\d+$`: a negative number, which is a value and not an option.
fn is_negative_number(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('-') else {
        return false;
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    match rest.split_once('.') {
        None => !rest.is_empty() && digits(rest),
        Some((int, frac)) => digits(int) && !frac.is_empty() && digits(frac),
    }
}

/// argparse's `_parse_optional`: an argument that starts with `-` is taken for an option
/// (and so cannot be the value of the one before it) unless it is just `-`, a negative
/// number, or contains a space.
fn looks_like_option(v: &str) -> bool {
    v.starts_with('-') && v.len() > 1 && !is_negative_number(v) && !v.contains(' ')
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
        let attached = (!arg.starts_with("--") && arg.len() > 2)
            .then(|| arg.get(..2))
            .flatten()
            .filter(|p| specs.iter().any(|s| s.short == Some(*p)));
        let (name, inline) = match (attached, arg.split_once('=')) {
            // argparse: `-oVALUE` and `-o=VALUE` both give the short option VALUE.
            (Some(p), _) => {
                let rest = &arg[2..];
                (
                    p.to_string(),
                    Some(rest.strip_prefix('=').unwrap_or(rest).to_string()),
                )
            }
            (None, Some((n, v))) if n.starts_with("--") => (n.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let matches: Vec<&Opt> = if name.starts_with("--") {
            match specs.iter().find(|s| s.long == name) {
                Some(s) => vec![s],
                None => specs.iter().filter(|s| s.long.starts_with(&name)).collect(),
            }
        } else if name.starts_with('-') && name.len() > 1 {
            specs
                .iter()
                .filter(|s| s.short == Some(name.as_str()))
                .collect()
        } else {
            vec![]
        };
        let spec = match matches.as_slice() {
            [s] => *s,
            [] => {
                return Err(fail(format!(
                    "unrecognized arguments: {}",
                    argv[i..].join(" ")
                )))
            }
            many => {
                let names: Vec<&str> = many.iter().map(|s| s.long).collect();
                return Err(fail(format!(
                    "ambiguous option: {name} could match {}",
                    names.join(", ")
                )));
            }
        };
        let d = dest(spec.long);
        let shown = arg_label(spec);
        match spec.kind {
            Kind::Flag => {
                if inline.is_some() {
                    return Err(fail(format!(
                        "argument {shown}: ignored explicit argument '{}'",
                        inline.unwrap_or_default()
                    )));
                }
                a.flags.push(d);
            }
            Kind::Value | Kind::Append => {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        match argv.get(i) {
                            Some(v) if !looks_like_option(v) => v.clone(),
                            _ => {
                                return Err(fail(format!(
                                    "argument {shown}: expected one argument"
                                )))
                            }
                        }
                    }
                };
                if !spec.choices.is_empty() && !spec.choices.contains(&v.as_str()) {
                    let ch: Vec<String> = spec.choices.iter().map(|c| format!("'{c}'")).collect();
                    return Err(fail(format!(
                        "argument {shown}: invalid choice: '{v}' (choose from {})",
                        ch.join(", ")
                    )));
                }
                if spec.int && v.trim().parse::<i64>().is_err() {
                    return Err(fail(format!("argument {shown}: invalid int value: '{v}'")));
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
    let missing: Vec<&str> = specs
        .iter()
        .filter(|s| s.required && a.get(&dest(s.long)).is_none())
        .map(|s| s.long)
        .collect();
    if !missing.is_empty() {
        return Err(fail(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        )));
    }
    Ok(a)
}

fn int_arg(a: &Args, k: &str, default: i64) -> i64 {
    a.get(k)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// ───────────────────────────── shared helpers ───────────────────────────────

fn emit_json(rc: i32, fields: Vec<(&str, Json)>) -> i32 {
    let mut doc = Json::obj()
        .with("ok", (rc == 0).into())
        .with("exit_code", Json::Int(i64::from(rc)));
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
    let parts: Vec<&str> = s
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
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
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
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
        && v.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'-')
        });
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
    let fd = fsops::open(
        path,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
    .map_err(|e| e.msg)?;
    let st = fsops::fstat(&fd).map_err(|e| e.msg)?;
    if !fsops::is_type(&st, libc::S_IFREG) {
        return Err(format!("{path} is not a regular file"));
    }
    if st.st_size as u64 > max {
        return Err(format!(
            "{path} is unexpectedly large ({} bytes)",
            st.st_size
        ));
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
        let Json::Obj(items) = self.json() else {
            return vec![];
        };
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
    torrc_service_names_at(TORRC_PATH, keys)
}

fn torrc_service_names_at(torrc: &str, keys: &str) -> Vec<String> {
    let Ok(b) = std::fs::read(torrc) else {
        return vec![];
    };
    service_names_in_torrc(&String::from_utf8_lossy(&b), keys)
}

/// The services a torrc configures under `keys` (or the sealed RAM copy of it).
fn service_names_in_torrc(text: &str, keys: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let Some(v) = hsdir_value(line) else { continue };
        let p = py_path(&v);
        let (parent, name) = p.rsplit_once('/').unwrap_or(("", p.as_str()));
        let parent = if parent.is_empty() && p.starts_with('/') {
            "/"
        } else {
            parent
        };
        // Sealed keys: Tor's HiddenServiceDir is the RAM copy, named the same.
        let sealed_copy =
            py_path(parent) == crate::sealed::RAM && py_path(keys) == py_path(&default_keys_env());
        if (py_path(parent) == py_path(keys) || sealed_copy)
            && name_ok(name)
            && !names.iter().any(|n| n == name)
        {
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
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return torrc_service_names(keys);
        }
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
    in_container_from(
        std::env::var("HIDDENFORGE_IN_CONTAINER").ok().as_deref(),
        std::path::Path::new(TORRC_PATH).exists(),
    )
}

/// Inside the image when the marker variable is exactly "1", or a torrc exists.
fn in_container_from(marker: Option<&str>, torrc_exists: bool) -> bool {
    marker == Some("1") || torrc_exists
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
        .any(|d| {
            !d.is_empty()
                && access(&format!("{d}/{tool}"), libc::X_OK)
                && !is_dir(&format!("{d}/{tool}"))
        })
}

fn access(path: &str, mode: i32) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
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
            vec![
                ("name", "hiddenforge".into()),
                ("version", VERSION.into()),
                ("contract_version", Json::Int(CONTRACT_VERSION)),
            ],
        );
    }
    println!("hiddenforge {VERSION} (contract {CONTRACT_VERSION})");
    EXIT_OK
}

fn cmd_info(a: &Args) -> i32 {
    let text = std::fs::read_to_string(MANIFEST).unwrap_or_default();
    let Some(m) = py::parse(&text) else {
        return emit_json(
            EXIT_FAIL,
            vec![("error", format!("cannot read {MANIFEST}").into())],
        );
    };
    if a.flag("json") {
        println!("{}", py::dumps(&m, true, Some(2)));
        return EXIT_OK;
    }
    for line in info_lines(&m) {
        println!("{line}");
    }
    EXIT_OK
}

/// The human `info` lines for a manifest (scripts/hiddenforge cmd_info).
fn info_lines(m: &Json) -> Vec<String> {
    let s = |j: Option<&Json>| match j {
        Some(Json::Str(s)) => s.clone(),
        Some(Json::Int(i)) => i.to_string(),
        _ => String::new(),
    };
    let vol = match m.get("volumes") {
        Some(Json::Arr(v)) => v.first().cloned().unwrap_or(Json::Null),
        _ => Json::Null,
    };
    vec![
        format!(
            "{} {} (contract {})",
            s(m.get("name")),
            s(m.get("version")),
            s(m.get("contract_version"))
        ),
        format!("  image:   {}", s(m.get("image"))),
        format!("  tor:     {}", s(m.get("tor_version"))),
        format!(
            "  address: {}",
            s(m.get("address").and_then(|x| x.get("command")))
        ),
        format!(
            "  health:  {} (field: {})",
            s(m.get("health").and_then(|x| x.get("command"))),
            s(m.get("health").and_then(|x| x.get("ready_field")))
        ),
        format!(
            "  keys:    {} -> {}",
            s(vol.get("path")),
            s(vol.get("host_suggestion"))
        ),
    ]
}

fn not_ready_error(keys: &str, name: &str) -> String {
    let d = join(keys, name);
    if !is_dir(&d) {
        return "address not generated yet (no key directory for this service)".into();
    }
    if !access(&d, libc::R_OK | libc::X_OK) {
        return format!(
            "address not published yet: {d} exists but is not readable by this user, and {} does not exist. Under Docker it appears once the service is reachable. Under rootless Podman, 2.1.x never writes it (3.0 does); pass --container <name> to read the address from inside the container.",
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
    let entries: Vec<Entry> = service_names(&keys)
        .iter()
        .map(|n| address_for(&keys, n))
        .collect();
    if !is_dir(&keys) {
        return emit_json(
            EXIT_USAGE,
            vec![
                ("keys", keys.as_str().into()),
                (
                    "error",
                    format!("key directory {keys} does not exist").into(),
                ),
            ],
        );
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
    let inconsistent: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.source.as_deref() == Some("inconsistent"))
        .collect();
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
            (
                "addresses",
                Json::Arr(entries.iter().map(Entry::json).collect()),
            ),
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
            println!(
                "{} {}",
                e.name,
                e.onion
                    .clone()
                    .unwrap_or_else(|| "(not generated yet)".into())
            );
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
        checks.push(check(
            false,
            "key directory exists",
            &format!("{keys} not found"),
            "fail",
        ));
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
            let mut sealed = false;
            let modes = fsops::lstat(&d).and_then(|s| {
                let k = match fsops::lstat(&format!("{d}/{SECRET_FILE}")) {
                    Err(e) if e.errno == Some(libc::ENOENT) => {
                        sealed = true;
                        fsops::lstat(&format!("{d}/{SECRET_FILE}.enc"))?
                    }
                    other => other?,
                };
                Ok((fsops::imode(&s), fsops::imode(&k)))
            });
            match modes {
                Err(e) if e.is_permission() => closed.push(name),
                Err(e) => checks.push(check(
                    false,
                    &format!("key modes for {name}"),
                    &format!("cannot stat: {}", e.msg),
                    "fail",
                )),
                Ok((dm, sm)) => {
                    checks.push(check(
                        dm == 0o700,
                        &format!("key dir {name} is 0700"),
                        &format!("mode={}", oct(dm)),
                        "fail",
                    ));
                    let kind = if sealed { "sealed" } else { "secret" };
                    checks.push(check(
                        sm == 0o600,
                        &format!("{kind} key {name} is 0600"),
                        &format!("mode={}", oct(sm)),
                        "fail",
                    ));
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
        .filter(|c| {
            c.get("ok") == Some(&Json::Bool(false))
                && c.get("severity") == Some(&Json::Str("fail".into()))
        })
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
                (
                    "failures",
                    Json::Arr(failures.into_iter().map(Json::Str).collect()),
                ),
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
        println!(
            "[{}] {}: {}",
            if okc { "ok  " } else { "FAIL" },
            s("check"),
            s("detail")
        );
    }
    rc
}

// ── setup ──

pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"@%+=:,./-_".contains(&b))
    {
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
    (1..=253).contains(&h.len())
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn py_isdigit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn port_ok(s: &str) -> bool {
    py_isdigit(s) && s.parse::<u64>().is_ok_and(|p| (1..=65535).contains(&p))
}

fn parse_backend(b: &str) -> Result<(String, String), String> {
    let Some((host, port)) = b.rsplit_once(':') else {
        return Err(format!(
            "--backend must be host:port, got {}",
            py::py_repr(b)
        ));
    };
    if host.is_empty() || !port_ok(port) {
        return Err(format!(
            "--backend must be host:port with port 1-65535, got {}",
            py::py_repr(b)
        ));
    }
    if !host_ok(host) {
        return Err(format!("invalid backend host {}", py::py_repr(host)));
    }
    Ok((host.into(), port.into()))
}

fn parse_service_spec(spec: &str) -> Result<(String, String), String> {
    let p: Vec<&str> = spec.split(':').collect();
    if p.len() != 4 {
        return Err(format!(
            "service mapping must be name:onionport:host:port, got {}",
            py::py_repr(spec)
        ));
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
    pub passphrase_file: Option<&'a str>,
}

fn render_compose(services: &Services, o: &SetupOpts) -> String {
    let svc = sorted(services);
    let mut env_lines: String = svc
        .iter()
        .map(|(n, v)| format!("      {}: \"{}\"\n", env_var(n), v.join(",")))
        .collect();
    let (mut secret_use, mut secret_def) = (String::new(), String::new());
    if let Some(pp) = o.passphrase_file {
        env_lines +=
            "      HIDDENFORGE_KEY_PASSPHRASE_FILE: /run/secrets/hiddenforge_key_passphrase\n";
        secret_use = "    secrets:\n      - hiddenforge_key_passphrase\n".into();
        secret_def = format!(
            "\nsecrets:\n  hiddenforge_key_passphrase:\n    file: {}\n",
            yaml_dq(pp)
        );
    }
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
    let hosts: Vec<String> = hosts
        .into_iter()
        .filter(|h| container_ok(h) && !is_ip_literal(h))
        .collect();
    let dep_block = if hosts.is_empty() {
        String::new()
    } else {
        format!(
            "    depends_on:\n{}",
            hosts
                .iter()
                .map(|h| format!("      - {h}\n"))
                .collect::<String>()
        )
    };
    let docker = o.runtime == "docker";
    let apparmor = if docker {
        "      - apparmor=docker-default\n"
    } else {
        ""
    };
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
    let compose_cmd = if o.runtime == "podman" {
        "podman-compose"
    } else {
        "docker compose"
    };
    let restart = if o.runtime == "podman" {
        "always"
    } else {
        "unless-stopped"
    };
    let healthcheck = if o.runtime == "podman" {
        String::new()
    } else {
        "    healthcheck:\n      test: [\"CMD\", \"su-exec\", \"tor\", \"python3\", \"/usr/local/bin/healthcheck.py\"]\n      interval: 60s\n      timeout: 10s\n      start_period: 120s\n      retries: 3\n".to_string()
    };
    let example = &svc[0].0;
    let mut header = format!(
        "# hiddenforge compose fragment (hiddenforge v{VERSION}, contract {CONTRACT_VERSION})."
    );
    if o.no_root {
        header += "\n# No-root mode: the container runs as the tor user (100:101) with no capabilities at all.";
    }
    let user_line = if o.no_root {
        "    user: \"100:101\"\n"
    } else {
        ""
    };
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
{secret_use}{healthcheck}{dep_block}{secret_def}"
    )
}

fn render_deploy(services: &Services, o: &SetupOpts) -> String {
    let names: Vec<String> = sorted(services)
        .iter()
        .map(|(n, _)| shlex_quote(n))
        .collect();
    let names = names.join(" ");
    let keys_q = shlex_quote(o.keys);
    let disp = o
        .keys
        .replace('\\', "\\\\")
        .replace('"', "'")
        .replace('$', "\\$")
        .replace('`', "'");
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
    let mut own_step = if !o.no_root {
        String::new()
    } else if o.runtime == "podman" {
        format!("echo \"==> Handing the key directory to the tor user (100:101)\"\npodman unshare chown -R 100:101 {keys_q}\n")
    } else {
        format!(
            "if [ \"$(stat -c %u:%g {keys_q})\" != \"100:101\" ]; then\n    echo \"==> Handing the key directory to the tor user (100:101); sudo asks once\"\n    sudo chown -R 100:101 {keys_q}\nfi\n"
        )
    };
    if let Some(pp) = o.passphrase_file {
        let pp_q = shlex_quote(pp);
        own_step += &format!(
            "if [ ! -s {pp_q} ]; then\n    echo \"==> Creating a random key passphrase (keys are encrypted at rest)\"\n    (umask 077; head -c 32 /dev/urandom | base64 > {pp_q})\n    echo \"    BACK IT UP, separately from the key directory: without it the\"\n    echo \"    address is lost. Kept on this disk it protects backups only.\"\nfi\n"
        );
        if o.no_root {
            if o.runtime == "podman" {
                own_step += &format!("podman unshare chown 100:101 {pp_q}\n");
            } else {
                own_step += &format!("if [ \"$(stat -c %u:%g {pp_q})\" != \"100:101\" ]; then\n    sudo chown 100:101 {pp_q}\nfi\n");
            }
        }
    }
    let status_line = shlex_quote(&format!(
        "  hiddenforge status --container {} --keys {keys_q}",
        o.container
    ));
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
    let block: Vec<String> = svc
        .iter()
        .map(|(n, v)| format!("  {n}: {}=\"{}\"", env_var(n), v.join(",")))
        .collect();
    let block = block.join("\n");
    let names: Vec<&str> = svc.iter().map(|(n, _)| n.as_str()).collect();
    let names = names.join(", ");
    let compose_cmd = if o.runtime == "podman" {
        "podman-compose"
    } else {
        "docker compose"
    };
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
/// Create a file that must not exist yet: never reuses or follows anything already at
/// that name (a planted file or link is an error, and nothing is written through it).
fn create_new(path: &str, mode: u32) -> Result<fsops::Fd, String> {
    fsops::open(
        path,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        mode,
    )
    .map_err(|e| e.msg)
}

fn write_bytes_nofollow(path: &str, data: &[u8], mode: u32) -> Result<(), String> {
    match fsops::lstat(path) {
        Ok(st) if !fsops::is_type(&st, libc::S_IFREG) => {
            return Err(format!(
                "[Errno 17] refusing to replace {path}: it is not a regular file"
            ))
        }
        _ => {}
    }
    let (dir, base) = path.rsplit_once('/').unwrap_or((".", path));
    let tmp = format!("{dir}/.{base}.{}.tmp", random_hex8());
    let r = (|| -> Result<(), String> {
        let fd = create_new(&tmp, mode)?;
        fsops::write_all(&fd, data).map_err(|e| e.msg)?;
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
        let cwd = std::env::current_dir()
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/".into());
        py_path(&format!("{cwd}/{p}"))
    };
    std::fs::canonicalize(&abs)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or(abs)
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
            add(
                &mut services,
                validate_name(&name).map_err(usage)?,
                format!("{onion_port}:{h}:{p}"),
            );
        }
        if services.is_empty() {
            if a.flag("non_interactive") || a.flag("json") || !stdin_tty() {
                return Err(usage(
                    "--backend service:port is required (or --service/--services)".into(),
                ));
            }
            eprint!("Backend service:port (e.g. web:80): ");
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0
                || py::strip_str(&line).is_empty()
            {
                return Err((EXIT_ABORTED, "aborted at prompt".into()));
            }
            let (h, p) = parse_backend(py::strip_str(&line)).map_err(usage)?;
            add(
                &mut services,
                validate_name(&name).map_err(usage)?,
                format!("{onion_port}:{h}:{p}"),
            );
        }
        let out = py_path(a.get("out").unwrap_or("./hiddenforge-deploy"));
        std::fs::create_dir_all(&out).map_err(|e| {
            (
                EXIT_FAIL,
                py::oserror_path(e.raw_os_error().unwrap_or(0), &out),
            )
        })?;
        let outputs = [
            "compose.service.yml",
            "deploy.sh",
            "README.txt",
            "hiddenforge.json",
        ];
        let existing: Vec<&str> = outputs
            .iter()
            .copied()
            .filter(|p| fsops::lstat(&join(&out, p)).is_ok())
            .collect();
        if !existing.is_empty() && !a.flag("force") {
            return Err(usage(format!(
                "{out} already contains {}; pass --force to overwrite",
                existing.join(", ")
            )));
        }
        let odd: Vec<&str> = existing
            .iter()
            .copied()
            .filter(|p| {
                fsops::lstat(&join(&out, p)).is_ok_and(|s| !fsops::is_type(&s, libc::S_IFREG))
            })
            .collect();
        if !odd.is_empty() {
            return Err(usage(format!(
                "refusing to replace {} in {out}: not a regular file (a symlink, directory or FIFO is not something setup wrote)",
                odd.join(", ")
            )));
        }
        let image = validate_image_ref(&a.get("image").map_or_else(default_image, String::from))
            .map_err(usage)?;
        let keys = validate_keys_dir(a.get("keys").unwrap_or(DEFAULT_KEYS)).map_err(usage)?;
        let container =
            validate_container(a.get("container").unwrap_or(DEFAULT_CONTAINER)).map_err(usage)?;
        let runtime = a.get("runtime").unwrap_or("docker").to_string();
        if !(1..=65535).contains(&onion_port) {
            return Err(usage(format!(
                "--onion-port must be 1-65535, got {onion_port}. Emitting it anyway would write a compose file whose service the container drops at boot, with the reason only in the container log."
            )));
        }
        let no_root = a.flag("no_root");
        let pp_file = if a.flag("encrypt_keys") {
            Some(
                validate_keys_dir(a.get("passphrase_file").unwrap_or("./key-passphrase.txt"))
                    .map_err(usage)?,
            )
        } else {
            None
        };
        let o = SetupOpts {
            image: &image,
            keys: &keys,
            container: &container,
            runtime: &runtime,
            no_root,
            passphrase_file: pp_file.as_deref(),
        };
        let fail = |e: String| (EXIT_FAIL, e);
        write_bytes_nofollow(
            &join(&out, "compose.service.yml"),
            render_compose(&services, &o).as_bytes(),
            0o644,
        )
        .map_err(fail)?;
        write_bytes_nofollow(
            &join(&out, "deploy.sh"),
            render_deploy(&services, &o).as_bytes(),
            0o755,
        )
        .map_err(fail)?;
        write_bytes_nofollow(
            &join(&out, "README.txt"),
            render_readme(&services, &o).as_bytes(),
            0o644,
        )
        .map_err(fail)?;
        let compose_cmd = if runtime == "podman" {
            "podman-compose"
        } else {
            "docker compose"
        };
        let merge = format!(
            "{compose_cmd} -f compose.yml -f {} up -d",
            shlex_quote(&format!("{out}/compose.service.yml"))
        );
        let svc = sorted(&services);
        let svc_list: Vec<Json> = svc
            .iter()
            .map(|(n, v)| {
                Json::obj()
                    .with("name", n.as_str().into())
                    .with("env_var", env_var(n).into())
                    .with("env_value", v.join(",").into())
                    .with(
                        "address_command",
                        format!("hiddenforge show --json --name {n}").into(),
                    )
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
            .with(
                "backend",
                firstmaps[0].split(':').nth(1).unwrap_or("").into(),
            )
            .with("image", image.as_str().into())
            .with("keys", keys.as_str().into())
            .with("container", container.as_str().into())
            .with("runtime", runtime.as_str().into())
            // From the mapping, like "backend": --onion-port applies only to the
            // --backend form, and a --service mapping carries its own port.
            .with(
                "onion_port",
                Json::Int(
                    firstmaps[0]
                        .split(':')
                        .next()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(onion_port),
                ),
            )
            .with("output_dir", realpath_lenient(&out).into())
            .with("merge", merge.as_str().into())
            .with(
                "address_command",
                format!("hiddenforge show --json --name {first}").into(),
            )
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
        if let Some(pp) = &pp_file {
            descriptor.set("encrypt_keys", true.into());
            descriptor.set("passphrase_file", pp.as_str().into());
        }
        write_bytes_nofollow(
            &join(&out, "hiddenforge.json"),
            (py::dumps(&descriptor, true, Some(2)) + "\n").as_bytes(),
            0o644,
        )
        .map_err(fail)?;
        if a.flag("json") {
            let mut doc = Json::obj()
                .with("ok", true.into())
                .with("exit_code", Json::Int(0));
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
    let Ok(st) = fsops::lstat(p) else {
        return false;
    };
    if fsops::is_type(&st, libc::S_IFLNK) {
        return false;
    }
    let parent = format!("{}/..", py_path(p));
    let Ok(ps) = fsops::lstat(&parent) else {
        return false;
    };
    st.st_dev != ps.st_dev || st.st_ino == ps.st_ino
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            fsops::lstat(&p).is_ok_and(|s| fsops::is_type(&s, libc::S_IFDIR))
                && !access(&p, libc::W_OK)
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
        std::fs::rename(join(keys, e), join(&archive, e))
            .map_err(|er| (EXIT_FAIL, py::oserror(er.raw_os_error().unwrap_or(0))))?;
    }
    Ok((archive, entries))
}

fn cmd_rotate(a: &Args) -> i32 {
    let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
    if !is_dir(&keys) {
        return emit_json(
            EXIT_USAGE,
            vec![
                ("keys", keys.as_str().into()),
                (
                    "error",
                    format!("key directory {keys} does not exist").into(),
                ),
            ],
        );
    }
    if py::strip_str(a.get("confirm").unwrap_or("")) != "ROTATE" {
        return emit_json(
            EXIT_USAGE,
            vec![
                ("keys", keys.as_str().into()),
                (
                    "error",
                    "refusing to destroy an identity without --confirm ROTATE".into(),
                ),
            ],
        );
    }
    let res = if ismount(&keys) {
        rotate_inside(&keys).map(|(a, m)| (a, Some(m)))
    } else {
        if !access(&keys, libc::W_OK) {
            return emit_json(
                EXIT_FAIL,
                vec![
                    ("keys", keys.as_str().into()),
                    ("error", "key directory is not writable".into()),
                ],
            );
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
        Err((EXIT_USAGE, e)) => emit_json(
            EXIT_USAGE,
            vec![("keys", keys.as_str().into()), ("error", e.into())],
        ),
        Err((code, e)) => emit_json(code, vec![("error", e.into())]),
        Ok((archived, moved)) => {
            let note = "A running container keeps serving the old address from memory until it is restarted; restart it to generate the new one.";
            if a.flag("json") {
                let moved = moved.map_or(Json::Null, |m| {
                    Json::Arr(m.into_iter().map(Json::Str).collect())
                });
                return emit_json(
                    EXIT_OK,
                    vec![
                        ("keys", keys.as_str().into()),
                        ("archived", archived.into()),
                        ("moved", moved),
                        ("note", note.into()),
                    ],
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
    ["age", "gpg"]
        .iter()
        .find(|t| which(t))
        .map(|t| t.to_string())
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
    format!(
        "{tool}: [Errno 2] No such file or directory: {}. {}",
        py::py_repr(tool),
        no_tool_error()
    )
}

fn cmd_backup(a: &Args) -> i32 {
    let r = (|| -> Result<i32, String> {
        let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
        if !is_dir(&keys) {
            return Err(format!("key directory {keys} does not exist"));
        }
        let ni = a.get("passphrase_file").is_some() || !stdin_tty();
        let tool =
            pick_tool(a.get("tool"), a.get("out").unwrap_or(""), ni).ok_or_else(no_tool_error)?;
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
        // --tool is age or gpg here: the parser refuses openssl.
        let tool = pick_tool(a.get("tool"), "", ni).ok_or_else(no_tool_error)?;
        passphrase_check(a, &tool)?;
        Err(tool_missing(&tool))
    })();
    r.unwrap_or_else(|e| emit_json(EXIT_USAGE, vec![("error", e.into())]))
}

// ── vanity (vanity.py) ──

fn emit_vanity(rc: i32, json: bool, payload: Vec<(&str, Json)>, human: &str) -> i32 {
    if json {
        let mut doc = Json::obj()
            .with("ok", (rc == 0).into())
            .with("exit_code", Json::Int(i64::from(rc)));
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
    for c in [
        env.as_deref(),
        Some("/usr/local/bin/mkp224o"),
        Some("/usr/bin/mkp224o"),
    ]
    .into_iter()
    .flatten()
    {
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

/// Make a directory only its owner can enter (Python: mkdir(mode=0o700), mkdtemp).
/// The mode is passed to mkdir(2), so it is never briefly wider than 0700 under any umask.
fn mkdir_private(path: &str, recursive: bool) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(recursive)
        .mode(0o700)
        .create(path)
}

fn benchmark(seconds: i64, threads: i64) -> Result<f64, String> {
    use std::io::BufRead;
    let seconds = seconds.max(1);
    let generator = mkp224o_path()?;
    let tmp = format!("/tmp/hf-bench-{}", random_hex8());
    mkdir_private(&tmp, false).map_err(|e| e.to_string())?;
    let spawned = std::process::Command::new(generator)
        .args([
            "-d",
            &tmp,
            "-t",
            &threads.to_string(),
            "-n",
            "0",
            "-S",
            "1",
            "-T",
            "zzzzzzzzzz",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e.to_string());
        }
    };
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
                let v: String = line[i + 9..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(r) = v.parse::<f64>() {
                    best = r;
                }
            }
        }
    }
    // SAFETY: signalling our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    // A generator that ignores SIGTERM gets 5 s, then SIGKILL (Python: wait(5), kill()).
    let grace = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < grace {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&tmp);
    if best <= 0.0 {
        return Err("mkp224o produced no statistics; cannot benchmark".into());
    }
    Ok(best)
}

fn vanity_generate(
    prefix: &str,
    name: &str,
    out: &str,
    threads: i64,
    force: bool,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<Json, (i32, String)> {
    let target = join(out, name);
    let exists = fsops::lstat(&target).is_ok();
    if exists && !force {
        return Err((EXIT_USAGE, format!(
            "{target} already exists. Refusing to overwrite a key set: the key IS the .onion address and there is no recovery. Pass --force to archive the old one and generate a fresh address."
        )));
    }
    mkdir_private(out, true).map_err(|e| (EXIT_FAIL, e.to_string()))?;
    let tmp = join(out, &format!("hf-vanity-{}", random_hex8()));
    mkdir_private(&tmp, false).map_err(|e| (EXIT_FAIL, e.to_string()))?;
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
            let tail: String = err
                .chars()
                .rev()
                .take(500)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            return Err((
                EXIT_FAIL,
                format!(
                    "mkp224o exited {}: {tail}",
                    outp.status.code().unwrap_or(-1)
                ),
            ));
        }
        if generated.len() != 1 {
            return Err((
                EXIT_FAIL,
                format!(
                    "expected exactly one generated .onion directory, found {}",
                    generated.len()
                ),
            ));
        }
        let dir_onion = generated[0].clone();
        let src = join(&tmp, &dir_onion);
        if !fsops::is_onion(&dir_onion) {
            return Err((
                EXIT_FAIL,
                format!(
                    "generator produced an invalid address name: {}",
                    py::py_repr(&dir_onion)
                ),
            ));
        }
        if !dir_onion.starts_with(prefix) {
            return Err((
                EXIT_FAIL,
                format!(
                    "generated address {dir_onion} does not start with prefix {}",
                    py::py_repr(prefix)
                ),
            ));
        }
        let file_onion = read_nofollow(&join(&src, HOSTNAME_FILE), 8192)
            .ok()
            .filter(|d| d.is_ascii())
            .map(|d| py::strip_str(&String::from_utf8_lossy(&d)).to_string())
            .filter(|t| fsops::is_onion(t));
        if file_onion.as_deref() != Some(dir_onion.as_str()) {
            return Err((
                EXIT_FAIL,
                format!(
                    "hostname file ({}) disagrees with directory name ({})",
                    file_onion.map_or("None".into(), |f| py::py_repr(&f)),
                    py::py_repr(&dir_onion)
                ),
            ));
        }
        let pk = read_nofollow(&join(&src, PUBLIC_FILE), 8192).map_err(|e| (EXIT_FAIL, e))?;
        let pk = if pk.len() == 64 && pk.starts_with(PUBLIC_TAG) {
            pk[32..].to_vec()
        } else {
            pk
        };
        let derived = sha3::derive_onion(&pk).ok_or((
            EXIT_FAIL,
            format!(
                "{PUBLIC_FILE}: expected 64 bytes (tagged) or 32 bytes (bare), got {}",
                pk.len()
            ),
        ))?;
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
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .collect();
    names.sort();
    for n in names {
        let Ok(fd) = fsops::open(&join(dir, &n), libc::O_RDONLY | libc::O_NOFOLLOW, 0) else {
            continue;
        };
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
        Opt {
            required: true,
            ..o("--prefix", Kind::Value)
        },
        o("--name", Kind::Value),
        o("--out", Kind::Value),
        Opt {
            int: true,
            ..o("--threads", Kind::Value)
        },
        o("--force", Kind::Flag),
        Opt {
            int: true,
            ..o("--uid", Kind::Value)
        },
        Opt {
            int: true,
            ..o("--gid", Kind::Value)
        },
        o("--bench", Kind::Flag),
        Opt {
            int: true,
            ..o("--seconds", Kind::Value)
        },
        o("--json", Kind::Flag),
    ];
    let a = match parse("vanity.py", &specs, argv) {
        Ok(a) => a,
        Err(rc) => return rc,
    };
    let json = a.flag("json");
    let prefix = a.get("prefix").unwrap_or("");
    let name = a.get("name").unwrap_or(DEFAULT_NAME);
    if !(1..=12).contains(&prefix.len())
        || !prefix
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
    {
        let r = py::py_repr(prefix);
        return emit_vanity(
            EXIT_USAGE,
            json,
            vec![(
                "error",
                format!(
                    "invalid prefix {r}: use base32 characters a-z and 2-7 (no 0,1,8,9), max 12"
                )
                .into(),
            )],
            &format!("error: invalid prefix {r}"),
        );
    }
    if !name_ok(name) {
        let r = py::py_repr(name);
        return emit_vanity(
            EXIT_USAGE,
            json,
            vec![("error", format!("invalid name {r}").into())],
            &format!("error: invalid name {r}"),
        );
    }
    let threads = match int_arg(&a, "threads", 0) {
        t if t > 0 => t,
        _ => std::thread::available_parallelism().map_or(1, |n| n.get() as i64),
    }
    .clamp(1, 256);
    let seconds = int_arg(&a, "seconds", 5);
    let rate = match benchmark(seconds, threads) {
        Ok(r) => r,
        Err(e) => {
            return emit_vanity(
                EXIT_USAGE,
                json,
                vec![("error", format!("benchmark failed: {e}").into())],
                &format!("error: benchmark failed: {e}"),
            )
        }
    };
    let rows: Vec<(i64, i64, f64)> = (1..=8)
        .map(|l: u32| (i64::from(l), 32i64.pow(l), 32f64.powi(l as i32) / rate))
        .collect();
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
            (
                "keys_per_sec_per_thread",
                Json::Float(py::py_round(rate / threads as f64, 2)),
            ),
            ("difficulty", table),
        ];
        if json {
            return emit_vanity(EXIT_OK, true, payload, "");
        }
        let commas = |x: f64| {
            let s = format!("{:.0}", x);
            let (neg, d) = s
                .strip_prefix('-')
                .map_or((false, s.as_str()), |r| (true, r));
            let mut out = String::new();
            for (i, ch) in d.chars().enumerate() {
                if i > 0 && (d.len() - i) % 3 == 0 {
                    out.push(',');
                }
                out.push(ch);
            }
            if neg {
                format!("-{out}")
            } else {
                out
            }
        };
        let mut lines = vec![
            format!(
                "mkp224o throughput: {} keys/sec ({threads} threads, {} keys/sec/thread)",
                commas(rate),
                commas(rate / threads as f64)
            ),
            String::new(),
            "prefix len   average attempts        expected time".into(),
        ];
        for (l, at, s) in &rows {
            lines.push(format!(
                "{l:>9}   {:>18}   {:>13}",
                commas(*at as f64),
                human_duration(*s)
            ));
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
    let out = a.get("out").map_or_else(
        || {
            std::env::var("HIDDENFORGE_KEYS_DIR")
                .unwrap_or_else(|_| "/var/lib/tor/hidden_service".into())
        },
        String::from,
    );
    let uid = a.get("uid").and_then(|v| v.trim().parse().ok());
    let gid = a.get("gid").and_then(|v| v.trim().parse().ok());
    match vanity_generate(
        prefix,
        name,
        &py_path(&out),
        threads,
        a.flag("force"),
        uid,
        gid,
    ) {
        Err((code, e)) => emit_vanity(
            code,
            json,
            vec![("error", e.clone().into()), ("name", name.into())],
            &format!("error: {e}"),
        ),
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
            let Json::Obj(items) = r else {
                return EXIT_FAIL;
            };
            let payload: Vec<(&str, Json)> = items.into_iter().map(|(k, v)| (leak(k), v)).collect();
            emit_vanity(EXIT_OK, json, payload, &human)
        }
    }
}

// ── client-auth: restricted discovery (opt-in) ─────────────────────────────

fn cmd_client_auth(a: &Args, op: &str) -> i32 {
    let keys = py_path(&a.get("keys").map_or_else(default_keys_env, String::from));
    let name = a.get("name").unwrap_or(DEFAULT_NAME);
    if let Err(e) = validate_name(name) {
        return emit_json(EXIT_USAGE, vec![("error", e.into())]);
    }
    // The files belong to the tor user, who must be able to read them and whose
    // directory they live in; written as root they would be root's.
    if crate::privs::is_root() {
        if let Err(e) = crate::compat::become_tor() {
            return emit_json(
                EXIT_FAIL,
                vec![(
                    "error",
                    format!("cannot switch to the tor user: {e}").into(),
                )],
            );
        }
    }
    let svc = join(&keys, name);
    if !is_dir(&svc) {
        return emit_json(
            EXIT_USAGE,
            vec![("error", format!("no service {name} in {keys}: start it once, or generate its key, before authorizing clients").into())],
        );
    }
    let restart = "Restart the container: Tor reads the authorized clients when it starts.";
    match op {
        "list" => match crate::clientauth::list(&keys, name) {
            Ok(c) => {
                if a.flag("json") {
                    return emit_json(
                        EXIT_OK,
                        vec![
                            ("name", name.into()),
                            ("clients", Json::Arr(c.into_iter().map(Json::Str).collect())),
                        ],
                    );
                }
                if c.is_empty() {
                    println!(
                        "{name}: no client authorization (anyone with the address can connect)"
                    );
                } else {
                    println!("{name}: only these clients can connect: {}", c.join(", "));
                }
                EXIT_OK
            }
            Err(e) => emit_json(EXIT_FAIL, vec![("error", e.into())]),
        },
        "add" | "remove" => {
            let Some(client) = a.get("client") else {
                return emit_json(
                    EXIT_USAGE,
                    vec![("error", "--client <name> is required".into())],
                );
            };
            if !crate::clientauth::client_name_ok(client) {
                return emit_json(
                    EXIT_USAGE,
                    vec![("error", format!("invalid client name {}: lowercase letters, digits, '-' and '_', max 63", py::safe_str(client)).into())],
                );
            }
            if op == "remove" {
                return match crate::clientauth::remove(&keys, name, client) {
                    Ok(removed) => {
                        if !a.flag("json") {
                            println!(
                                "{name}: {}. {restart}",
                                if removed {
                                    format!("removed {client}")
                                } else {
                                    format!("{client} was not authorized")
                                }
                            );
                        }
                        if a.flag("json") {
                            emit_json(
                                EXIT_OK,
                                vec![
                                    ("name", name.into()),
                                    ("client", client.into()),
                                    ("removed", removed.into()),
                                ],
                            )
                        } else {
                            EXIT_OK
                        }
                    }
                    Err(e) => emit_json(EXIT_FAIL, vec![("error", e.into())]),
                };
            }
            let onion =
                read_pubkey(&format!("{svc}/{PUBLIC_FILE}")).and_then(|k| sha3::derive_onion(&k));
            let Some(onion) = onion else {
                return emit_json(
                    EXIT_USAGE,
                    vec![("error", format!("{name} has no public key yet: start it once before authorizing clients").into())],
                );
            };
            match crate::clientauth::add(&keys, name, client, &onion) {
                Ok(private_line) => {
                    let first = crate::clientauth::list(&keys, name)
                        .map(|c| c.len() == 1)
                        .unwrap_or(false);
                    if a.flag("json") {
                        return emit_json(
                            EXIT_OK,
                            vec![
                                ("name", name.into()),
                                ("client", client.into()),
                                ("onion", onion.as_str().into()),
                                ("client_auth_private", private_line.as_str().into()),
                                ("first_client", first.into()),
                            ],
                        );
                    }
                    println!("{name}: authorized client {client}.");
                    if first {
                        println!("This is the first client: from the next start, ONLY authorized clients can reach {onion}.");
                    }
                    println!("{restart}");
                    println!();
                    println!("Give this line to {client}, over a channel you trust, and nowhere else. It is shown once and not stored:");
                    println!("{private_line}");
                    println!();
                    println!("The client saves it as a file ending in .auth_private in the directory its torrc names with");
                    println!("ClientOnionAuthDir (Tor Browser: paste the key part when it asks for the onion's key).");
                    EXIT_OK
                }
                Err(e) => emit_json(EXIT_FAIL, vec![("error", e.into())]),
            }
        }
        _ => unreachable!("the dispatcher passes add, remove or list"),
    }
}

// ── unseal-keys: turn key encryption at rest off ────────────────────────────

/// Service names from the `<NAME>_TOR_SERVICE_HOSTS` variables, as the torrc
/// builder derives them.
fn env_service_names() -> Vec<String> {
    names_from_env_keys(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()))
}

fn names_from_env_keys(keys: impl Iterator<Item = String>) -> Vec<String> {
    let mut names: Vec<String> = keys
        .filter_map(|k| {
            k.strip_suffix("_TOR_SERVICE_HOSTS")
                .map(|n| n.to_lowercase().replace('_', "-"))
        })
        .filter(|n| name_ok(n))
        .collect();
    names.sort();
    names.dedup();
    names
}

fn cmd_unseal_keys(a: &Args) -> i32 {
    let Some(pf) = a
        .get("passphrase_file")
        .map(String::from)
        .or_else(crate::sealed::passphrase_file)
    else {
        return emit_json(
            EXIT_USAGE,
            vec![(
                "error",
                format!(
                    "no passphrase: pass --passphrase-file or set {}",
                    crate::sealed::ENV
                )
                .into(),
            )],
        );
    };
    // Read the passphrase first (it may be readable by root only), then drop.
    // `-` is stdin: the host CLI pipes it in, so no file is shared with the container.
    let pass = match if pf == "-" {
        crate::keycrypt::read_passphrase_stdin()
    } else {
        crate::keycrypt::read_passphrase(&pf)
    } {
        Ok(p) => p,
        Err(e) => return emit_json(EXIT_FAIL, vec![("error", e.into())]),
    };
    if crate::privs::is_root() {
        if let Err(e) = crate::compat::become_tor() {
            return emit_json(
                EXIT_FAIL,
                vec![(
                    "error",
                    format!("cannot switch to the tor user: {e}").into(),
                )],
            );
        }
    }
    let names = match a.get("name") {
        Some(n) => {
            if let Err(e) = validate_name(n) {
                return emit_json(EXIT_USAGE, vec![("error", e.into())]);
            }
            vec![n.to_string()]
        }
        None => env_service_names(),
    };
    if names.is_empty() {
        return emit_json(
            EXIT_USAGE,
            vec![("error", "no service named: pass --name, or run it in the tor service, where <NAME>_TOR_SERVICE_HOSTS is set".into())],
        );
    }
    let mut done = Vec::new();
    let mut skipped = Vec::new();
    for n in &names {
        match crate::sealed::unseal_to_volume(n, &pass.0) {
            Ok(Some(msg)) => {
                if !a.flag("json") {
                    println!("{msg}");
                }
                done.push(Json::Str(n.clone()));
            }
            Ok(None) => {
                if !a.flag("json") {
                    println!("{n}: no sealed key; nothing to do");
                }
                skipped.push(Json::Str(n.clone()));
            }
            Err(e) => {
                return emit_json(
                    EXIT_FAIL,
                    vec![("error", e.into()), ("unsealed", Json::Arr(done))],
                )
            }
        }
    }
    if a.flag("json") {
        return emit_json(
            EXIT_OK,
            vec![
                ("unsealed", Json::Arr(done)),
                ("not_sealed", Json::Arr(skipped)),
            ],
        );
    }
    println!(
        "Remove {} and the passphrase secret from the compose file before the next start; otherwise the key is sealed again.",
        crate::sealed::ENV
    );
    EXIT_OK
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
                o("--encrypt-keys", Kind::Flag),
                o("--passphrase-file", Kind::Value),
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
        "client-auth" => match rest.split_first() {
            Some((op, r)) if matches!(op.as_str(), "add" | "remove" | "list") => parse(
                &format!("hiddenforge client-auth {op}"),
                &[keys, o("--name", Kind::Value), o("--client", Kind::Value), json],
                r,
            )
            .map_or_else(|c| c, |a| cmd_client_auth(&a, op)),
            _ => emit_json(
                EXIT_USAGE,
                vec![("error", "usage: hiddenforge client-auth {add,remove,list} [--name <service>] [--client <name>] [--keys DIR] [--json]".into())],
            ),
        },
        "unseal-keys" => parse(
            "hiddenforge unseal-keys",
            &[o("--name", Kind::Value), o("--passphrase-file", Kind::Value), json],
            rest,
        )
        .map_or_else(|c| c, |a| cmd_unseal_keys(&a)),
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
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn create_new_refuses_an_existing_file_or_link_and_writes_nothing_through_it() {
        let d = scratch("cnew");
        let victim = format!("{d}/victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::os::unix::fs::symlink(&victim, format!("{d}/link")).unwrap();
        std::fs::write(format!("{d}/file"), b"keep").unwrap();
        for name in ["link", "file"] {
            let Err(e) = create_new(&format!("{d}/{name}"), 0o600) else {
                panic!("{name}: opened an existing entry");
            };
            assert!(e.contains("File exists"), "{name}: {e}");
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(create_new(&format!("{d}/new"), 0o600).is_ok());
    }

    #[test]
    fn parse_takes_short_option_values_the_argparse_ways() {
        let specs = [
            Opt {
                short: Some("-o"),
                ..o("--out", Kind::Value)
            },
            o("--force", Kind::Flag),
        ];
        let out = |args: &[&str]| {
            let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            parse("t", &specs, &v)
                .ok()
                .and_then(|a| a.get("out").map(String::from))
        };
        for form in [
            &["-o", "dir"][..],
            &["-odir"],
            &["-o=dir"],
            &["--out=dir"],
            &["--o", "dir"],
        ] {
            assert_eq!(out(form).as_deref(), Some("dir"), "{form:?}");
        }
        assert_eq!(out(&["-o=a=b"]).as_deref(), Some("a=b"));
        assert_eq!(out(&["-o="]).as_deref(), Some(""));
        assert_eq!(out(&["-xdir"]), None, "unknown short option");
    }

    // ── refusal paths (mutation sample, 2026-11-08: none of these were tested) ──

    #[test]
    fn names_must_be_lowercase_alnum_and_hyphen() {
        for good in ["myapp", "a", "9lives", "my-app-2", &"a".repeat(63)] {
            assert!(name_ok(good), "{good:?} should be accepted");
        }
        for bad in [
            "",
            "-app",
            "App",
            "my_app",
            "my app",
            "../x",
            "a.b",
            &"a".repeat(64),
            "é",
        ] {
            assert!(!name_ok(bad), "{bad:?} must be refused");
        }
    }

    #[test]
    fn container_names_cannot_inject_yaml_or_flags() {
        for good in ["tor", "hf3e2e-tor-1", "a.b_c-d", "9"] {
            assert!(
                validate_container(good).is_ok() && container_ok(good),
                "{good:?}"
            );
        }
        // 2.x shipped a fragment where a crafted --container added `privileged: true`.
        for bad in [
            "",
            "-privileged",
            "_x",
            "tor:\n    privileged: true",
            "a b",
            "a/b",
            "tor;id",
            "$(id)",
        ] {
            assert!(
                validate_container(bad).is_err() && !container_ok(bad),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn image_refs_refuse_flags_spaces_and_newlines() {
        for good in [
            "sambent.dev/sam/hiddenforge:latest",
            "hf3:dev",
            "dhi.io/static@sha256:36ef09f98be60351289f3aaf36a4328e2121821dce7f8f85ba099efef43bd329",
        ] {
            assert!(validate_image_ref(good).is_ok(), "{good:?}");
        }
        for bad in [
            "",
            "--privileged",
            "-x",
            "a b",
            "a\nb",
            "a;b",
            "a$b",
            &format!("a{}", "b".repeat(255)),
        ] {
            assert!(validate_image_ref(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn key_dir_paths_refuse_control_characters_and_length() {
        assert!(validate_keys_dir("./tor-keys").is_ok());
        assert!(validate_keys_dir(&"a".repeat(4096)).is_ok());
        assert!(validate_keys_dir(&"a".repeat(4097)).is_err());
        assert!(validate_keys_dir("").is_err());
        for c in ["\n", "\r", "\t", "\x00", "\x1b", "\x7f"] {
            assert!(
                validate_keys_dir(&format!("./k{c}x")).is_err(),
                "{c:?} must be refused"
            );
        }
    }

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("hf-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn read_nofollow_refuses_symlinks_dirs_and_oversize_and_reads_exactly() {
        let d = scratch("rn");
        let f = format!("{d}/f");
        std::fs::write(&f, b"0123456789").unwrap();
        assert_eq!(read_nofollow(&f, 10).unwrap(), b"0123456789");
        assert_eq!(read_nofollow(&f, 11).unwrap(), b"0123456789");
        assert!(read_nofollow(&f, 9).is_err(), "over the cap");
        std::fs::write(format!("{d}/empty"), b"").unwrap();
        assert_eq!(read_nofollow(&format!("{d}/empty"), 0).unwrap(), b"");
        std::os::unix::fs::symlink(&f, format!("{d}/link")).unwrap();
        assert!(
            read_nofollow(&format!("{d}/link"), 100).is_err(),
            "a symlink is never followed"
        );
        assert!(read_nofollow(&d, 100).is_err(), "a directory is not a file");
        let big = vec![b'x'; 200_000];
        std::fs::write(format!("{d}/big"), &big).unwrap();
        assert_eq!(
            read_nofollow(&format!("{d}/big"), 200_000).unwrap(),
            big,
            "multi-read files intact"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    const ONION: &str = "qtwidir57ll3rbtxwql5557yp7z3eb72mgbxn7wex7yofzn5tnooqpqd.onion";

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn onion_files_are_validated() {
        let d = scratch("on");
        let w = |n: &str, b: &[u8]| {
            std::fs::write(format!("{d}/{n}"), b).unwrap();
            read_onion_file(&format!("{d}/{n}"))
        };
        assert_eq!(
            w("ok", format!("{ONION}\n").as_bytes()).as_deref(),
            Some(ONION)
        );
        assert_eq!(w("bare", ONION.as_bytes()).as_deref(), Some(ONION));
        assert_eq!(w("junk", b"not an onion\n"), None);
        assert_eq!(w("upper", ONION.to_uppercase().as_bytes()), None);
        assert_eq!(
            w(
                "utf8",
                "qtwidir57ll3rbtxwql5557yp7z3eb72mgbxn7wex7yofzn5tnooqpqé.onion".as_bytes()
            ),
            None
        );
        assert_eq!(read_onion_file(&format!("{d}/missing")), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    fn pubkey_file(key: &[u8; 32]) -> Vec<u8> {
        let mut v = PUBLIC_TAG.to_vec();
        v.resize(32, 0);
        v.extend_from_slice(key);
        v
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn public_keys_need_the_tag_and_exact_length() {
        let d = scratch("pk");
        let key = [7u8; 32];
        let w = |n: &str, b: &[u8]| {
            std::fs::write(format!("{d}/{n}"), b).unwrap();
            read_pubkey(&format!("{d}/{n}"))
        };
        assert_eq!(w("tagged", &pubkey_file(&key)), Some(key.to_vec()));
        assert_eq!(w("raw", &key), Some(key.to_vec()), "a bare 32-byte key");
        let mut wrong = pubkey_file(&key);
        wrong[0] = b'X';
        assert_eq!(w("badtag", &wrong), None);
        assert_eq!(w("short", &pubkey_file(&key)[..63]), None);
        let mut long = pubkey_file(&key);
        long.push(0);
        assert_eq!(w("long", &long), None);
        assert_eq!(w("31", &key[..31]), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn address_for_says_where_the_address_came_from() {
        let keys = scratch("af");
        let svc = format!("{keys}/myapp");
        std::fs::create_dir_all(&svc).unwrap();
        let key = [9u8; 32];
        let derived = sha3::derive_onion(&key).unwrap();
        // Only the public key: the address is derived from it.
        std::fs::write(format!("{svc}/{PUBLIC_FILE}"), pubkey_file(&key)).unwrap();
        let e = address_for(&keys, "myapp");
        assert_eq!(
            (e.onion.as_deref(), e.source.as_deref()),
            (Some(derived.as_str()), Some("derived"))
        );
        // A published <name>.onion is preferred to deriving.
        std::fs::write(format!("{keys}/myapp.onion"), format!("{derived}\n")).unwrap();
        let e = address_for(&keys, "myapp");
        assert_eq!(
            (e.source.as_deref(), e.derived_matches),
            (Some("published"), Some(true))
        );
        // The hostname file is preferred to both, and must agree with the key.
        std::fs::write(format!("{svc}/{HOSTNAME_FILE}"), format!("{derived}\n")).unwrap();
        let e = address_for(&keys, "myapp");
        assert_eq!(
            (e.source.as_deref(), e.derived_matches),
            (Some("hostname"), Some(true))
        );
        assert!(e.json().get("hostname_onion").is_none());
        // A hostname that disagrees with the key is reported, never trusted.
        std::fs::write(format!("{svc}/{HOSTNAME_FILE}"), format!("{ONION}\n")).unwrap();
        let e = address_for(&keys, "myapp");
        assert_eq!(
            (e.onion.as_deref(), e.source.as_deref()),
            (None, Some("inconsistent"))
        );
        assert_eq!(e.derived_matches, Some(false));
        assert_eq!(
            (e.hostname_onion.as_deref(), e.derived_onion.as_deref()),
            (Some(ONION), Some(derived.as_str()))
        );
        let j = e.json();
        assert!(j.get("hostname_onion").is_some() && j.get("derived_onion").is_some());
        assert_eq!(e.fields().len(), 10);
        assert!(e.fields().iter().any(|(k, _)| *k == "derived_onion"));
        assert_eq!(e.key_path, format!("{svc}/{SECRET_FILE}"));
        // Nothing at all: no address, no source.
        let e = address_for(&keys, "other");
        assert_eq!((e.onion, e.source, e.derived_matches), (None, None, None));
        let _ = std::fs::remove_dir_all(&keys);
    }

    #[test]
    fn hidden_service_dir_lines_are_parsed_strictly() {
        assert_eq!(
            hsdir_value("HiddenServiceDir /var/lib/tor/hidden_service/a").as_deref(),
            Some("/var/lib/tor/hidden_service/a")
        );
        assert_eq!(
            hsdir_value("   HiddenServiceDir\t/x/a  ").as_deref(),
            Some("/x/a")
        );
        assert_eq!(hsdir_value("HiddenServiceDir"), None);
        assert_eq!(hsdir_value("HiddenServiceDir   "), None);
        assert_eq!(hsdir_value("HiddenServiceDirX /x/a"), None);
        assert_eq!(hsdir_value("HiddenServiceDir /x/a extra"), None);
        assert_eq!(hsdir_value("# HiddenServiceDir /x/a"), None);
        assert_eq!(hsdir_value("HiddenServicePort 80 1.2.3.4:80"), None);
    }

    #[test]
    fn torrc_service_names_under_the_key_root_only() {
        let t = "HiddenServiceDir     /var/lib/tor/hidden_service/blog\n\
                 HiddenServiceDir     /var/lib/tor/hidden_service/shop\n\
                 HiddenServiceDir     /var/lib/tor/hidden_service/blog\n\
                 HiddenServiceDir     /elsewhere/evil\n\
                 HiddenServiceDir     /var/lib/tor/hidden_service/Bad_Name\n\
                 HiddenServiceDir     /var/lib/tor/hs-ram/vault\n";
        let root = "/var/lib/tor/hidden_service";
        // The sealed RAM copy (hs-ram/<name>) counts only for the default key root.
        let mut want = vec!["blog", "shop"];
        if py_path(&default_keys_env()) == root {
            want.push("vault");
        }
        assert_eq!(service_names_in_torrc(t, root), want);
        assert_eq!(service_names_in_torrc(t, "/elsewhere"), vec!["evil"]);
        assert_eq!(
            service_names_in_torrc(t, &default_keys_env())
                .iter()
                .filter(|n| *n == "vault")
                .count(),
            1,
            "the default root sees its sealed RAM copy"
        );
        assert!(service_names_in_torrc("", root).is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn small_helpers() {
        assert_eq!(oct(0o751), "0o751");
        assert!(py_isdigit("0123") && !py_isdigit("12a") && !py_isdigit(""));
        assert!(
            which("sh") || which("bash"),
            "a shell is on the test host's PATH"
        );
        assert!(!which("definitely-not-a-command-hf"));
        assert!(!is_dir("/definitely/not/here") && is_dir("/"));
    }

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

    // ── helpers shared by the tests below ──

    /// A scratch directory that is made traversable again and removed even when a test panics.
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("hf-cli-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Scratch(d)
        }
        fn path(&self, rel: &str) -> String {
            format!("{}/{rel}", self.0.display())
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            fn reopen(p: &std::path::Path) {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
                    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                    if let Ok(rd) = std::fs::read_dir(p) {
                        for e in rd.flatten() {
                            reopen(&e.path());
                        }
                    }
                }
            }
            reopen(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(p: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(p: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    // ── human_duration, random_hex8, now_secs (vanity.py human_duration is the reference) ──

    #[test]
    fn durations_read_like_the_python_generator_prints_them() {
        for (secs, want) in [
            (0.0, "<1s"),
            (0.5, "<1s"),
            (0.999, "<1s"),
            (1.0, "1s"),
            (1.4, "1s"),
            (1.5, "2s"),
            (2.5, "2s"),
            (59.4, "59s"),
            (59.5, "60s"),
            (60.0, "1.0m"),
            (3599.0, "60.0m"),
            (3599.9, "60.0m"),
            (3600.0, "1.0h"),
            (86399.0, "24.0h"),
            (86400.0, "1.0d"),
            (1e7, "115.7d"),
            (31535999.0, "365.0d"),
            (31536000.0, "1.0y"),
            (6.3e8, "20.0y"),
        ] {
            assert_eq!(human_duration(secs), want, "{secs} seconds");
        }
    }

    #[test]
    fn random_names_are_sixteen_fresh_hex_digits() {
        let all: Vec<String> = (0..64).map(|_| random_hex8()).collect();
        for h in &all {
            assert_eq!(h.len(), 16, "{h}");
            assert!(h
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
        let mut uniq = all.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), all.len(), "64 draws must all differ");
        assert!(all.iter().all(|h| h != "0000000000000000"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn the_clock_is_unix_seconds() {
        // SAFETY: time(2) with a null pointer.
        let c = unsafe { libc::time(std::ptr::null_mut()) } as u64;
        let n = now_secs();
        assert!(n >= 1_700_000_000, "{n}");
        assert!(n.abs_diff(c) <= 2, "{n} vs {c}");
    }

    // ── names and tool choice ──

    #[test]
    fn the_image_is_recognised_by_marker_or_torrc() {
        for (marker, torrc, want) in [
            (None, false, false),
            (Some("1"), false, true),
            (Some("0"), false, false),
            (Some("true"), false, false),
            (Some(""), false, false),
            (Some("11"), false, false),
            (None, true, true),
            (Some("0"), true, true),
            (Some("1"), true, true),
        ] {
            assert_eq!(in_container_from(marker, torrc), want, "{marker:?} {torrc}");
        }
    }

    #[test]
    fn service_names_come_from_variable_names() {
        let keys = [
            "MYAPP_TOR_SERVICE_HOSTS",
            "WEB_2_TOR_SERVICE_HOSTS",
            "myapp_TOR_SERVICE_HOSTS",
            "A_B_C_TOR_SERVICE_HOSTS",
            "TOR_SERVICE_HOSTS",
            "_TOR_SERVICE_HOSTS",
            "_LEAD_TOR_SERVICE_HOSTS",
            "UP.PER_TOR_SERVICE_HOSTS",
            "X_TOR_SERVICE_HOSTS_EXTRA",
            "PATH",
            "9_TOR_SERVICE_HOSTS",
        ];
        assert_eq!(
            names_from_env_keys(keys.iter().map(|k| k.to_string())),
            vec!["9", "a-b-c", "myapp", "web-2"]
        );
        let long = format!("{}_TOR_SERVICE_HOSTS", "A".repeat(64));
        assert!(names_from_env_keys([long].into_iter()).is_empty());
        assert!(names_from_env_keys(std::iter::empty()).is_empty());
    }

    #[test]
    fn the_torrc_is_read_from_the_path_it_is_given() {
        let s = Scratch::new("torrc");
        let t = s.path("torrc");
        std::fs::write(
            &t,
            b"HiddenServiceDir /k/b\nHiddenServiceDir /k/a\nHiddenServiceDir /other/c\n\xff\n",
        )
        .unwrap();
        assert_eq!(torrc_service_names_at(&t, "/k"), vec!["b", "a"]);
        assert!(torrc_service_names_at(&t, "/nope").is_empty());
        assert!(torrc_service_names_at(&s.path("absent"), "/k").is_empty());
    }

    // ── info ──

    #[test]
    fn info_lines_put_each_manifest_field_in_its_slot() {
        let m = py::parse(
            r#"{"name": "nm", "version": "9.8.7", "contract_version": 4, "image": "img:tag",
                "tor_version": "0.1.2", "address": {"command": "addr cmd"},
                "health": {"command": "hc cmd", "ready_field": "rdy"},
                "volumes": [{"path": "/v/p", "host_suggestion": "./h"}, {"path": "/second"}]}"#,
        )
        .unwrap();
        assert_eq!(
            info_lines(&m),
            vec![
                "nm 9.8.7 (contract 4)",
                "  image:   img:tag",
                "  tor:     0.1.2",
                "  address: addr cmd",
                "  health:  hc cmd (field: rdy)",
                "  keys:    /v/p -> ./h",
            ]
        );
        let s = py::parse(r#"{"contract_version": "5", "volumes": []}"#).unwrap();
        let lines = info_lines(&s);
        assert_eq!(lines[0], "  (contract 5)");
        assert_eq!(lines[5], "  keys:     -> ");
    }

    #[test]
    fn info_of_the_shipped_manifest() {
        // The repository's manifest.json: next to the crate in a checkout, or under
        // HIDDENFORGE_DIFF_REPO when the crate is built from a copy (mutation runs).
        let beside = concat!(env!("CARGO_MANIFEST_DIR"), "/../manifest.json").to_string();
        let path = if std::path::Path::new(&beside).exists() {
            beside
        } else {
            let repo = std::env::var("HIDDENFORGE_DIFF_REPO")
                .expect("manifest.json is not beside the crate: set HIDDENFORGE_DIFF_REPO");
            format!("{repo}/manifest.json")
        };
        let m = py::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        let lines = info_lines(&m);
        assert_eq!(lines.len(), 6);
        assert_eq!(
            lines[0],
            format!("hiddenforge {VERSION} (contract {CONTRACT_VERSION})")
        );
        assert_eq!(lines[1], "  image:   sambent.dev/sam/hiddenforge:latest");
        assert_eq!(
            lines[3],
            "  address: hiddenforge show --json [--name <service>] [--container <name>]"
        );
        assert_eq!(
            lines[4],
            "  health:  hiddenforge status --json (field: ready)"
        );
        assert_eq!(
            lines[5],
            "  keys:    /var/lib/tor/hidden_service -> ./tor-keys"
        );
        assert!(lines[2].starts_with("  tor:     0.") && lines[2].len() > 12);
    }

    // ── mounts, rotation, hardening, atomic writes ──

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn mount_points_are_found_by_device_and_symlinks_never_count() {
        let s = Scratch::new("mount");
        assert!(ismount("/"), "the root is its own parent");
        if std::path::Path::new("/proc/self").exists() {
            assert!(ismount("/proc"), "a different device from /");
        }
        std::fs::create_dir(s.path("sub")).unwrap();
        assert!(!ismount(&s.path("sub")));
        assert!(!ismount(&s.path("missing")));
        std::os::unix::fs::symlink("/", s.path("link")).unwrap();
        assert!(
            !ismount(&s.path("link")),
            "a symlink to / is not a mount point"
        );
        assert!(!ismount(&s.path("sub/../sub/missing")));
    }

    fn populate_volume(s: &Scratch) {
        std::fs::create_dir_all(s.path("keys/a")).unwrap();
        std::fs::write(s.path("keys/a/hostname"), b"a.onion\n").unwrap();
        std::fs::write(s.path("keys/b.onion"), b"b\n").unwrap();
        std::fs::create_dir_all(s.path("keys/.rotated-1")).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn rotating_inside_moves_every_entry_into_a_fresh_private_archive() {
        let s = Scratch::new("rot");
        populate_volume(&s);
        let keys = s.path("keys");
        let (archive, moved) = rotate_inside(&keys).unwrap();
        assert_eq!(
            moved,
            vec!["a", "b.onion"],
            "sorted, earlier archives left alone"
        );
        let name = archive.rsplit('/').next().unwrap();
        assert!(
            name.strip_prefix(".rotated-")
                .is_some_and(|t| t.len() == 10 && t.bytes().all(|b| b.is_ascii_digit())),
            "{name}"
        );
        assert!(archive.starts_with(&format!("{keys}/")));
        assert_eq!(mode_of(&archive), 0o700);
        assert_eq!(
            std::fs::read(format!("{archive}/a/hostname")).unwrap(),
            b"a.onion\n"
        );
        assert!(std::path::Path::new(&format!("{archive}/b.onion")).exists());
        assert!(!std::path::Path::new(&s.path("keys/a")).exists());
        assert!(!std::path::Path::new(&s.path("keys/b.onion")).exists());
        assert!(std::path::Path::new(&s.path("keys/.rotated-1")).is_dir());
        let mut left: Vec<String> = std::fs::read_dir(&keys)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec![".rotated-1".to_string(), name.to_string()]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn rotating_an_empty_volume_is_a_usage_error() {
        let s = Scratch::new("rotempty");
        std::fs::create_dir_all(s.path("keys/.rotated-5")).unwrap();
        let keys = s.path("keys");
        assert_eq!(
            rotate_inside(&keys),
            Err((EXIT_USAGE, format!("{keys} holds no identity to rotate")))
        );
        assert!(!std::path::Path::new(&s.path("keys/.rotated-5/.rotated-5")).exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn rotating_refuses_whole_when_one_directory_cannot_be_moved() {
        if crate::privs::is_root() {
            return; // root can move anything
        }
        let s = Scratch::new("rotstuck");
        populate_volume(&s);
        std::fs::create_dir_all(s.path("keys/z")).unwrap();
        chmod(&s.path("keys/z"), 0o500);
        chmod(&s.path("keys/a"), 0o500);
        let keys = s.path("keys");
        assert_eq!(
            rotate_inside(&keys),
            Err((
                EXIT_FAIL,
                "[Errno 13] cannot move a, z (not writable by this user); nothing was rotated. Run rotate where the service directories are writable, e.g. inside the container".to_string()
            ))
        );
        assert!(
            std::path::Path::new(&s.path("keys/a/hostname")).exists(),
            "nothing moved"
        );
        assert!(std::path::Path::new(&s.path("keys/b.onion")).exists());
        let archives = std::fs::read_dir(&keys)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".rotated-"))
            .count();
        assert_eq!(archives, 1, "no archive was created");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn only_unwritable_directories_block_a_rotation() {
        if crate::privs::is_root() {
            return;
        }
        let s = Scratch::new("rotfiles");
        std::fs::create_dir_all(s.path("keys")).unwrap();
        std::fs::write(s.path("keys/readonly.onion"), b"x").unwrap();
        chmod(&s.path("keys/readonly.onion"), 0o000);
        std::os::unix::fs::symlink("/proc", s.path("keys/link")).unwrap();
        let (archive, moved) = rotate_inside(&s.path("keys")).unwrap();
        assert_eq!(moved, vec!["link", "readonly.onion"]);
        assert!(std::fs::symlink_metadata(format!("{archive}/link")).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn rotation_numbers_archives_when_the_name_is_taken() {
        let s = Scratch::new("rotnum");
        std::fs::create_dir_all(s.path("keys/a")).unwrap();
        let now = now_secs();
        for t in now - 1..now + 4 {
            std::fs::create_dir(s.path(&format!("keys/.rotated-{t}"))).unwrap();
        }
        let (archive, _) = rotate_inside(&s.path("keys")).unwrap();
        let name = archive.rsplit('/').next().unwrap();
        assert!(
            name.strip_prefix(".rotated-")
                .and_then(|r| r.split_once('-'))
                .is_some_and(|(t, n)| t.len() == 10 && n == "1"),
            "{name}"
        );
        // a second rotation, with -1 taken as well, goes to -2
        std::fs::create_dir_all(s.path("keys/b")).unwrap();
        for t in now - 1..now + 4 {
            let _ = std::fs::create_dir(s.path(&format!("keys/.rotated-{t}-1")));
        }
        let (archive, _) = rotate_inside(&s.path("keys")).unwrap();
        assert!(archive.ends_with("-2"), "{archive}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn rotating_does_not_follow_a_symlinked_volume() {
        let s = Scratch::new("rotlink");
        std::fs::create_dir_all(s.path("real/a")).unwrap();
        std::os::unix::fs::symlink("real", s.path("keys")).unwrap();
        let err = rotate_inside(&s.path("keys")).unwrap_err();
        assert_eq!(err.0, EXIT_FAIL);
        assert!(err.1.starts_with("[Errno 20] Not a directory"), "{}", err.1);
        assert!(std::path::Path::new(&s.path("real/a")).is_dir());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn hardening_sets_modes_on_descriptors_and_leaves_symlinks_alone() {
        let s = Scratch::new("harden");
        let dir = s.path("svc");
        std::fs::create_dir(&dir).unwrap();
        for (n, m) in [
            ("hs_ed25519_secret_key", 0o644),
            ("hs_ed25519_public_key", 0o666),
            ("hostname", 0o600),
            ("zzz-extra", 0o640),
        ] {
            std::fs::write(format!("{dir}/{n}"), b"x").unwrap();
            chmod(&format!("{dir}/{n}"), m);
        }
        std::fs::write(s.path("victim"), b"v").unwrap();
        chmod(&s.path("victim"), 0o644);
        std::os::unix::fs::symlink(s.path("victim"), format!("{dir}/evil")).unwrap();
        chmod(&dir, 0o777);
        harden(&dir, None, None).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&format!("{dir}/hostname")), 0o644);
        for n in [
            "hs_ed25519_secret_key",
            "hs_ed25519_public_key",
            "zzz-extra",
        ] {
            assert_eq!(mode_of(&format!("{dir}/{n}")), 0o600, "{n}");
        }
        assert_eq!(
            mode_of(&s.path("victim")),
            0o644,
            "the link's target is untouched"
        );
        assert!(std::fs::symlink_metadata(format!("{dir}/evil"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn hardening_applies_the_requested_owner() {
        use std::os::unix::fs::MetadataExt;
        let s = Scratch::new("hardenown");
        let dir = s.path("svc");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(format!("{dir}/hostname"), b"x").unwrap();
        // SAFETY: plain getters.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        harden(&dir, Some(uid), Some(gid)).unwrap();
        // Another group the caller belongs to: the group id must really be applied.
        let mut groups = [0 as libc::gid_t; 64];
        // SAFETY: getgroups into a 64-entry buffer.
        let n = unsafe { libc::getgroups(64, groups.as_mut_ptr()) };
        if let Some(other) = groups[..n.max(0) as usize].iter().find(|g| **g != gid) {
            harden(&dir, None, Some(*other)).unwrap();
            for p in [dir.clone(), format!("{dir}/hostname")] {
                let md = std::fs::metadata(&p).unwrap();
                assert_eq!((md.uid(), md.gid()), (uid, *other), "{p}");
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn hardening_refuses_a_symlinked_or_missing_directory() {
        let s = Scratch::new("hardenlink");
        std::fs::create_dir(s.path("real")).unwrap();
        std::os::unix::fs::symlink("real", s.path("link")).unwrap();
        assert!(harden(&s.path("link"), None, None).is_err());
        assert!(harden(&s.path("absent"), None, None).is_err());
    }

    #[test]
    fn atomic_writes_set_the_exact_mode_and_replace_regular_files() {
        use std::os::unix::fs::MetadataExt;
        let s = Scratch::new("atomic");
        let f = s.path("out.txt");
        std::fs::write(&f, b"old").unwrap();
        chmod(&f, 0o600);
        let before = std::fs::metadata(&f).unwrap().ino();
        write_bytes_nofollow(&f, b"new contents", 0o755).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"new contents");
        assert_eq!(
            mode_of(&f),
            0o755,
            "the requested mode, whatever the old file or umask had"
        );
        assert_ne!(
            std::fs::metadata(&f).unwrap().ino(),
            before,
            "renamed into place"
        );
        write_bytes_nofollow(&f, b"", 0o644).unwrap();
        assert_eq!((std::fs::read(&f).unwrap(), mode_of(&f)), (vec![], 0o644));
        let big = vec![0xA5u8; 3 << 20];
        write_bytes_nofollow(&f, &big, 0o644).unwrap();
        assert_eq!(
            std::fs::read(&f).unwrap(),
            big,
            "a long write is finished in full"
        );
        let names: Vec<String> = std::fs::read_dir(&s.0)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["out.txt"], "no temporary file is left");
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn atomic_writes_never_replace_a_link_a_directory_or_a_fifo() {
        let s = Scratch::new("atomicno");
        std::fs::write(s.path("victim"), b"precious").unwrap();
        std::os::unix::fs::symlink("victim", s.path("link")).unwrap();
        std::fs::create_dir(s.path("dir")).unwrap();
        let fifo = std::ffi::CString::new(s.path("fifo")).unwrap();
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for n in ["link", "dir", "fifo"] {
            let p = s.path(n);
            assert_eq!(
                write_bytes_nofollow(&p, b"x", 0o644),
                Err(format!(
                    "[Errno 17] refusing to replace {p}: it is not a regular file"
                )),
                "{n}"
            );
        }
        assert_eq!(std::fs::read(s.path("victim")).unwrap(), b"precious");
        assert!(std::fs::symlink_metadata(s.path("link"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_dir(&s.0).unwrap().count(),
            4,
            "nothing was added"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a syscall or libc function miri cannot emulate")]
    fn atomic_writes_report_a_missing_directory() {
        let s = Scratch::new("atomicmiss");
        let e = write_bytes_nofollow(&s.path("nodir/f"), b"x", 0o644).unwrap_err();
        assert!(e.starts_with("[Errno 2] No such file or directory"), "{e}");
    }

    // ── argparse's option/value rules (python3 argparse is the reference) ──

    #[test]
    fn negative_numbers_are_values_and_other_dashed_words_are_options() {
        for number in ["-5", "-0", "-123", "-.5", "-1.5", "-0.25", "-10.0"] {
            assert!(is_negative_number(number), "{number}");
            assert!(!looks_like_option(number), "{number}");
        }
        for not_number in [
            "-", "-1x", "-1.", "-.", "-1e5", "-x", "--5", "5", "", "-1.2.3", "-.5x",
        ] {
            assert!(!is_negative_number(not_number), "{not_number}");
        }
        for option in [
            "-x", "--json", "--", "-1x", "-1.", "-.", "-1e5", "--na", "-oDIR", "--a=b",
        ] {
            assert!(looks_like_option(option), "{option}");
        }
        for value in [
            "-", "", "a", "5-", "-a b", "- 5", "-5 ", "--x y", "/tmp/x", "a-b",
        ] {
            assert!(!looks_like_option(value), "{value:?}");
        }
    }

    #[test]
    fn errors_name_every_spelling_of_the_option() {
        let specs = [
            Opt {
                short: Some("-o"),
                ..o("--out", Kind::Value)
            },
            o("--runtime", Kind::Value),
            Opt {
                int: true,
                ..o("--port", Kind::Value)
            },
            o("--force", Kind::Flag),
        ];
        assert_eq!(arg_label(&specs[0]), "-o/--out");
        assert_eq!(arg_label(&specs[1]), "--runtime");
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // a refusal is exit 2; the value after an option may be a negative number
        assert!(parse("t", &specs, &argv(&["-o"])).is_err());
        assert!(parse("t", &specs, &argv(&["-o", "--force"])).is_err());
        assert!(parse("t", &specs, &argv(&["--port", "-1x"])).is_err());
        assert_eq!(
            parse("t", &specs, &argv(&["--port", "-5"]))
                .unwrap()
                .get("port"),
            Some("-5")
        );
        assert_eq!(
            parse("t", &specs, &argv(&["-o", "-a b"]))
                .unwrap()
                .get("out"),
            Some("-a b")
        );
        assert!(parse("t", &specs, &argv(&["--port", "x"])).is_err());
        assert!(parse("t", &specs, &argv(&["--force=1"])).is_err());
    }
}
