//! Byte-compatible reproductions of the few Python behaviours whose output the
//! 2.x contract exposes: `_safe()` log escaping, `str(OSError)`, `str.strip()`,
//! and `json.dumps`. 3.0 must answer every existing consumer with the bytes 2.1.6
//! produced, so these are ported exactly rather than approximated.

use std::ffi::CStr;
use std::fmt::Write as _;

/// A string the way CPython sees an environment value: valid UTF-8 decodes to
/// characters, and each byte that is not valid UTF-8 becomes a lone surrogate
/// U+DC80..U+DCFF (the `surrogateescape` handler `os.environ` uses).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PyChar {
    C(char),
    Surr(u8),
}

pub type PyStr = Vec<PyChar>;

pub fn decode(bytes: &[u8]) -> PyStr {
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.extend(s.chars().map(PyChar::C));
                break;
            }
            Err(e) => {
                let good = e.valid_up_to();
                // SAFETY-free: the prefix was just validated.
                out.extend(
                    std::str::from_utf8(&rest[..good])
                        .unwrap_or("")
                        .chars()
                        .map(PyChar::C),
                );
                let bad = e.error_len().unwrap_or(rest.len() - good);
                for b in &rest[good..good + bad] {
                    out.push(PyChar::Surr(*b));
                }
                rest = &rest[good + bad..];
            }
        }
    }
    out
}

/// Code point used for ordering and for `\x..` escapes (a surrogate is 0xDC00 + byte).
pub fn ord(c: &PyChar) -> u32 {
    match c {
        PyChar::C(ch) => *ch as u32,
        PyChar::Surr(b) => 0xDC00 + u32::from(*b),
    }
}

pub fn from_str(s: &str) -> PyStr {
    s.chars().map(PyChar::C).collect()
}

/// The valid-UTF-8 form, or None if the value holds a surrogate.
pub fn to_string(s: &[PyChar]) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for c in s {
        match c {
            PyChar::C(ch) => out.push(*ch),
            PyChar::Surr(_) => return None,
        }
    }
    Some(out)
}

/// CPython's `str.isprintable()` for one character.
///
/// Exact for ASCII, Latin-1, every Unicode control, separator and format
/// character, and surrogates. CPython also treats *unassigned* code points as
/// non-printable; reproducing that needs the full Unicode database, so an
/// unassigned code point here is passed through. That only affects what a log
/// line shows for such a character: every character that can forge a line or
/// move a terminal cursor (controls, separators, bidi/format) is escaped.
fn is_printable(c: &PyChar) -> bool {
    let ch = match c {
        PyChar::Surr(_) => return false,
        PyChar::C(ch) => *ch,
    };
    let u = ch as u32;
    if u < 0x80 {
        return (0x20..0x7f).contains(&u);
    }
    if ch.is_control() {
        return false; // Cc
    }
    if ch.is_whitespace() {
        return false; // Zs (other than ASCII space), Zl, Zp
    }
    // Cf (format) characters, and private use (Co) which CPython also refuses.
    let format = matches!(u,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F);
    let private = matches!(u, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD);
    !(format || private)
}

/// entrypoint._safe(): escape non-printable characters as `\x{ord:02x}`.
pub fn safe(s: &[PyChar]) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s {
        if is_printable(c) {
            if let PyChar::C(ch) = c {
                out.push(*ch);
            }
        } else {
            let _ = write!(out, "\\x{:02x}", ord(c));
        }
    }
    out
}

pub fn safe_str(s: &str) -> String {
    safe(&from_str(s))
}

/// CPython's `str.isspace()` (what `str.strip()` removes).
pub fn is_py_space(c: &PyChar) -> bool {
    match c {
        PyChar::Surr(_) => false,
        PyChar::C(ch) => ch.is_whitespace() || matches!(*ch as u32, 0x1C..=0x1F),
    }
}

pub fn strip(s: &[PyChar]) -> &[PyChar] {
    let start = s.iter().position(|c| !is_py_space(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|c| !is_py_space(c))
        .map_or(start, |i| i + 1);
    &s[start..end]
}

pub fn strip_str(s: &str) -> &str {
    s.trim_matches(|ch: char| ch.is_whitespace() || matches!(ch as u32, 0x1C..=0x1F))
}

/// libc's message for an errno, exactly as `os.strerror()` returns it.
pub fn strerror(errno: i32) -> String {
    // SAFETY: strerror returns a pointer to a NUL-terminated static or
    // thread-local buffer; it is copied out before any other libc call.
    unsafe {
        let p = libc::strerror(errno);
        if p.is_null() {
            return format!("Unknown error {errno}");
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// `str(OSError(errno, strerror))`: "[Errno 13] Permission denied".
pub fn oserror(errno: i32) -> String {
    format!("[Errno {errno}] {}", strerror(errno))
}

/// `str(OSError)` with a filename, as raised by `open()`/`os.open()`.
pub fn oserror_path(errno: i32, path: &str) -> String {
    format!("[Errno {errno}] {}: {}", strerror(errno), py_repr(path))
}

/// `repr(str)` for the plain printable strings that reach error messages.
pub fn py_repr(s: &str) -> String {
    let use_double = s.contains('\'') && !s.contains('"');
    let q = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// errno from the last failed libc call.
pub fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// JSON, serialised exactly like CPython's json.dumps (ensure_ascii=True).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Insertion-ordered; `dumps` sorts when asked, as `sort_keys=True` does.
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }
    /// Set a key, replacing an existing one (dict assignment semantics).
    pub fn set(&mut self, k: &str, v: Json) {
        if let Json::Obj(items) = self {
            if let Some(slot) = items.iter_mut().find(|(key, _)| key == k) {
                slot.1 = v;
            } else {
                items.push((k.to_string(), v));
            }
        }
    }
    pub fn with(mut self, k: &str, v: Json) -> Json {
        self.set(k, v);
        self
    }
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(items) => items.iter().find(|(key, _)| key == k).map(|(_, v)| v),
            _ => None,
        }
    }
}

impl From<bool> for Json {
    fn from(v: bool) -> Self {
        Json::Bool(v)
    }
}
impl From<&str> for Json {
    fn from(v: &str) -> Self {
        Json::Str(v.to_string())
    }
}
impl From<String> for Json {
    fn from(v: String) -> Self {
        Json::Str(v)
    }
}
impl From<i64> for Json {
    fn from(v: i64) -> Self {
        Json::Int(v)
    }
}
impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(v: Option<T>) -> Self {
        v.map_or(Json::Null, Into::into)
    }
}

fn write_json_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let u = c as u32;
                if u > 0xFFFF {
                    let v = u - 0x10000;
                    let _ = write!(
                        out,
                        "\\u{:04x}\\u{:04x}",
                        0xD800 + (v >> 10),
                        0xDC00 + (v & 0x3FF)
                    );
                } else {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// json.dumps(value, sort_keys=sort, indent=indent).
pub fn dumps(v: &Json, sort: bool, indent: Option<usize>) -> String {
    let mut out = String::new();
    dump_into(&mut out, v, sort, indent, 0);
    out
}

fn dump_into(out: &mut String, v: &Json, sort: bool, indent: Option<usize>, level: usize) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Float(f) => out.push_str(&float_json(*f)),
        Json::Str(s) => write_json_str(out, s),
        Json::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                newline(out, indent, level + 1);
                dump_into(out, item, sort, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Json::Obj(items) => {
            if items.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut refs: Vec<&(String, Json)> = items.iter().collect();
            if sort {
                refs.sort_by(|a, b| a.0.cmp(&b.0));
            }
            out.push('{');
            for (i, (k, val)) in refs.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                newline(out, indent, level + 1);
                write_json_str(out, k);
                out.push_str(": ");
                dump_into(out, val, sort, indent, level + 1);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

/// CPython `repr(float)`: shortest round-trip digits, positional when the
/// decimal exponent is in [-4, 16), scientific ("1e+16", "1e-05") otherwise.
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let e = format!("{:e}", x.abs()); // e.g. "1.23456e2" (shortest digits)
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let sign = if x < 0.0 { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let n = digits.len() as i32;
        let s = if exp >= 0 {
            let int_len = exp + 1;
            if n <= int_len {
                format!("{digits}{}.0", "0".repeat((int_len - n) as usize))
            } else {
                format!(
                    "{}.{}",
                    &digits[..int_len as usize],
                    &digits[int_len as usize..]
                )
            }
        } else {
            format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
        };
        format!("{sign}{s}")
    } else {
        let m = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.clone()
        };
        let es = if exp < 0 { "-" } else { "+" };
        format!("{sign}{m}e{es}{:02}", exp.abs())
    }
}

/// json.dumps of a float (allow_nan=True: Infinity / -Infinity / NaN).
pub fn float_json(x: f64) -> String {
    if x.is_nan() {
        "NaN".into()
    } else if x.is_infinite() {
        if x > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else {
        float_repr(x)
    }
}

/// Python round(x, n) for the small n used here (round-half-even on the
/// decimal representation, as CPython does via correctly rounded strings).
pub fn py_round(x: f64, n: i32) -> f64 {
    let s = format!("{:.*}", n as usize, x);
    s.parse().unwrap_or(x)
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * level {
            out.push(' ');
        }
    }
}

// ---------------------------------------------------------------------------
// A small, strict JSON parser (for reading documents this program wrote:
// manifest.json, the healthcheck's own output).
// ---------------------------------------------------------------------------

pub fn parse(s: &str) -> Option<Json> {
    let b = s.as_bytes();
    let mut i = 0;
    let v = parse_value(b, &mut i, 0)?;
    skip_ws(b, &mut i);
    (i == b.len()).then_some(v)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn parse_value(b: &[u8], i: &mut usize, depth: usize) -> Option<Json> {
    if depth > 64 {
        return None;
    }
    skip_ws(b, i);
    match *b.get(*i)? {
        b'n' => lit(b, i, "null", Json::Null),
        b't' => lit(b, i, "true", Json::Bool(true)),
        b'f' => lit(b, i, "false", Json::Bool(false)),
        b'"' => parse_string(b, i).map(Json::Str),
        b'[' => {
            *i += 1;
            let mut items = Vec::new();
            skip_ws(b, i);
            if b.get(*i) == Some(&b']') {
                *i += 1;
                return Some(Json::Arr(items));
            }
            loop {
                items.push(parse_value(b, i, depth + 1)?);
                skip_ws(b, i);
                match *b.get(*i)? {
                    b',' => *i += 1,
                    b']' => {
                        *i += 1;
                        return Some(Json::Arr(items));
                    }
                    _ => return None,
                }
            }
        }
        b'{' => {
            *i += 1;
            let mut items: Vec<(String, Json)> = Vec::new();
            skip_ws(b, i);
            if b.get(*i) == Some(&b'}') {
                *i += 1;
                return Some(Json::Obj(items));
            }
            loop {
                skip_ws(b, i);
                let k = parse_string(b, i)?;
                skip_ws(b, i);
                if *b.get(*i)? != b':' {
                    return None;
                }
                *i += 1;
                let v = parse_value(b, i, depth + 1)?;
                if let Some(slot) = items.iter_mut().find(|(key, _)| *key == k) {
                    slot.1 = v;
                } else {
                    items.push((k, v));
                }
                skip_ws(b, i);
                match *b.get(*i)? {
                    b',' => *i += 1,
                    b'}' => {
                        *i += 1;
                        return Some(Json::Obj(items));
                    }
                    _ => return None,
                }
            }
        }
        b'-' | b'0'..=b'9' => {
            let start = *i;
            if b[*i] == b'-' {
                *i += 1;
            }
            let digits = *i;
            while *i < b.len() && b[*i].is_ascii_digit() {
                *i += 1;
            }
            // JSON (and json.loads) has no leading zeros: "0" yes, "01" no.
            if b.get(digits) == Some(&b'0') && *i - digits > 1 {
                return None;
            }
            std::str::from_utf8(&b[start..*i])
                .ok()?
                .parse::<i64>()
                .ok()
                .map(Json::Int)
        }
        _ => None,
    }
}

fn lit(b: &[u8], i: &mut usize, word: &str, v: Json) -> Option<Json> {
    if b.get(*i..*i + word.len())? == word.as_bytes() {
        *i += word.len();
        Some(v)
    } else {
        None
    }
}

fn parse_string(b: &[u8], i: &mut usize) -> Option<String> {
    if *b.get(*i)? != b'"' {
        return None;
    }
    *i += 1;
    let mut out: Vec<u16> = Vec::new();
    let mut raw: Vec<u8> = Vec::new();
    let flush = |raw: &mut Vec<u8>, out: &mut Vec<u16>| -> Option<()> {
        if !raw.is_empty() {
            out.extend(std::str::from_utf8(raw).ok()?.encode_utf16());
            raw.clear();
        }
        Some(())
    };
    loop {
        let c = *b.get(*i)?;
        *i += 1;
        match c {
            b'"' => {
                flush(&mut raw, &mut out)?;
                return String::from_utf16(&out).ok();
            }
            b'\\' => {
                flush(&mut raw, &mut out)?;
                let e = *b.get(*i)?;
                *i += 1;
                match e {
                    b'"' => out.push(u16::from(b'"')),
                    b'\\' => out.push(u16::from(b'\\')),
                    b'/' => out.push(u16::from(b'/')),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'n' => out.push(10),
                    b'r' => out.push(13),
                    b't' => out.push(9),
                    b'u' => {
                        let hex = b.get(*i..*i + 4)?;
                        // Exactly four hex digits: from_str_radix alone accepts "+123".
                        if !hex.iter().all(u8::is_ascii_hexdigit) {
                            return None;
                        }
                        out.push(u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
                        *i += 4;
                    }
                    _ => return None,
                }
            }
            c if c < 0x20 => return None,
            c => raw.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_what_json_loads_rejects() {
        for bad in [
            "\"\\u+123\"",
            "\"\\u-123\"",
            "01",
            "-01",
            "[00]",
            "{\"a\": 012}",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        assert_eq!(parse("0"), Some(Json::Int(0)));
        assert_eq!(parse("-0"), Some(Json::Int(0)));
        assert_eq!(
            parse("[0, 10, -7]"),
            Some(Json::Arr(vec![Json::Int(0), Json::Int(10), Json::Int(-7)]))
        );
        assert_eq!(parse("\"\\u00e9\\u00E9\""), Some(Json::Str("éé".into())));
    }

    #[test]
    fn safe_matches_python() {
        assert_eq!(safe_str("ok-name"), "ok-name");
        assert_eq!(safe_str("a\nb\x1b[1m"), "a\\x0ab\\x1b[1m");
        assert_eq!(safe_str("\u{200b}x"), "\\x200bx");
        assert_eq!(safe(&decode(b"a\xffb")), "a\\xdcffb");
        assert_eq!(safe_str("é"), "é");
    }

    #[test]
    fn strip_matches_python() {
        assert_eq!(to_string(strip(&from_str("\x1c 80 \t"))).unwrap(), "80");
        assert_eq!(strip_str("\u{a0}x\u{3000}"), "x");
    }

    #[test]
    fn dumps_matches_python() {
        let v = Json::obj()
            .with("version", "2.1.6".into())
            .with("ok", true.into())
            .with("exit_code", Json::Int(0))
            .with("name", "hiddenforge".into())
            .with("contract_version", Json::Int(1));
        assert_eq!(
            dumps(&v, true, None),
            r#"{"contract_version": 1, "exit_code": 0, "name": "hiddenforge", "ok": true, "version": "2.1.6"}"#
        );
        assert_eq!(
            dumps(&Json::Str("é\u{1F600}\"".into()), false, None),
            r#""\u00e9\ud83d\ude00\"""#
        );
        let nested = Json::obj().with("a", Json::Arr(vec![Json::Int(1), Json::obj()]));
        assert_eq!(
            dumps(&nested, false, Some(2)),
            "{\n  \"a\": [\n    1,\n    {}\n  ]\n}"
        );
    }

    #[test]
    fn float_repr_matches_python() {
        for (x, want) in [
            (123.0, "123.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (123.456, "123.456"),
            (2.5, "2.5"),
            (1e15, "1000000000000000.0"),
            (0.1, "0.1"),
            (33554432.0, "33554432.0"),
            (-2.75, "-2.75"),
        ] {
            assert_eq!(float_repr(x), want, "{x}");
        }
        assert_eq!(float_json(f64::INFINITY), "Infinity");
    }

    #[test]
    fn parse_roundtrip() {
        let s = r#"{"a": [1, true, null, "xé"], "b": {}}"#;
        let v = parse(s).unwrap();
        assert_eq!(
            dumps(&v, false, None),
            r#"{"a": [1, true, null, "x\u00e9"], "b": {}}"#
        );
        assert!(parse("{\"a\": 1,}").is_none());
    }

    #[test]
    fn oserror_format() {
        assert!(oserror(2).starts_with("[Errno 2] "));
    }

    #[test]
    fn parse_accepts_what_json_loads_accepts() {
        use Json::*;
        for (src, want) in [
            ("false", Bool(false)),
            ("true", Bool(true)),
            ("null", Null),
            ("[false]", Arr(vec![Bool(false)])),
            ("[]", Arr(vec![])),
            ("[ ]", Arr(vec![])),
            (" [ 1 , 2 ] ", Arr(vec![Int(1), Int(2)])),
            ("{\"a\": []}", Obj(vec![("a".into(), Arr(vec![]))])),
            ("{}", Obj(vec![])),
            ("{ }", Obj(vec![])),
            ("-5", Int(-5)),
            ("12", Int(12)),
            ("-0", Int(0)),
            ("[12]", Arr(vec![Int(12)])),
            ("[-3, 40]", Arr(vec![Int(-3), Int(40)])),
            ("\"\"", Str(String::new())),
            // a repeated key keeps its first position and takes the last value
            (
                "{\"a\": 1, \"b\": 2, \"a\": 3}",
                Obj(vec![("a".into(), Int(3)), ("b".into(), Int(2))]),
            ),
        ] {
            assert_eq!(parse(src), Some(want), "{src}");
        }
    }

    #[test]
    fn parse_rejects_malformed_documents() {
        for bad in [
            "",
            "[1,]",
            "[1 2]",
            "[",
            "]",
            "{\"a\" 1}",
            "{a: 1}",
            "{\"a\": 1,}",
            "{\"a\": }",
            "tru",
            "nul",
            "fals",
            "-",
            "- 1",
            "1 2",
            "[1] x",
            "\"abc",
            "\"\\",
            "{\"a\":",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn parse_string_escapes_match_json_loads() {
        for (src, want) in [
            (r#""\"""#, "\""),
            (r#""\\""#, "\\"),
            (r#""\/""#, "/"),
            (r#""\b""#, "\u{8}"),
            (r#""\f""#, "\u{c}"),
            (r#""\n""#, "\n"),
            (r#""\r""#, "\r"),
            (r#""\t""#, "\t"),
            (r#""\u00e9""#, "é"),
            (r#""é""#, "é"),
            (r#""\ud83d\ude00""#, "\u{1F600}"),
            ("\"😀\"", "😀"),
            (r#""a\u0041b""#, "aAb"),
            (r#""\u0000""#, "\0"),
            (r#""x\ty""#, "x\ty"),
        ] {
            assert_eq!(parse(src), Some(Json::Str(want.into())), "{src}");
        }
        assert_eq!(
            parse(r#"{"k\n": "v\"w"}"#),
            Some(Json::Obj(vec![("k\n".into(), Json::Str("v\"w".into()))]))
        );
    }

    #[test]
    fn parse_string_rejects_what_json_loads_rejects() {
        for bad in [
            "\"a\u{1}b\"",
            "\"a\nb\"",
            "\"a\tb\"",
            "\"\\q\"",
            "\"\\u12\"",
            "\"\\uzzzz\"",
            "\"\\u12G4\"",
            "\"\\x41\"",
            "\"abc",
            "\"\\",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn nesting_is_capped_at_65_levels() {
        let arr = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&arr(65)).is_some());
        assert!(parse(&arr(66)).is_none());
        let obj = |n: usize| format!("{}{{}}{}", "{\"a\": ".repeat(n - 1), "}".repeat(n - 1));
        assert!(parse(&obj(65)).is_some());
        assert!(parse(&obj(66)).is_none());
    }

    #[test]
    fn py_round_is_half_even_on_the_exact_binary_value() {
        for (x, n, want) in [
            (2.675, 2, 2.67),
            (0.5, 0, 0.0),
            (1.5, 0, 2.0),
            (2.5, 0, 2.0),
            (1234.5678, 1, 1234.6),
            (0.125, 2, 0.12),
            (7.0, 3, 7.0),
        ] {
            assert_eq!(py_round(x, n), want, "round({x}, {n})");
        }
    }

    #[test]
    fn decode_turns_each_undecodable_byte_into_a_lone_surrogate() {
        use PyChar::{Surr, C};
        assert_eq!(decode(b""), vec![]);
        assert_eq!(decode(b"ok\xc3\xa9"), from_str("oké"));
        assert_eq!(decode(b"\xe2\x82"), vec![Surr(0xe2), Surr(0x82)]);
        assert_eq!(decode(b"a\xe2\x82"), vec![C('a'), Surr(0xe2), Surr(0x82)]);
        assert_eq!(
            decode(b"\xe2\x28\xa1"),
            vec![Surr(0xe2), C('('), Surr(0xa1)]
        );
        assert_eq!(
            decode(b"\xf0\x9f\x98"),
            vec![Surr(0xf0), Surr(0x9f), Surr(0x98)]
        );
        assert_eq!(decode(b"\xff\xfe"), vec![Surr(0xff), Surr(0xfe)]);
        assert_eq!(
            decode(b"x\xffy\xe2\x82"),
            vec![C('x'), Surr(0xff), C('y'), Surr(0xe2), Surr(0x82)]
        );
    }

    #[test]
    fn errno_text_is_libcs_and_oserror_adds_the_path_repr() {
        assert_eq!(strerror(libc::ENOENT), "No such file or directory");
        assert_eq!(strerror(libc::EACCES), "Permission denied");
        assert_eq!(oserror(libc::EACCES), "[Errno 13] Permission denied");
        assert_eq!(
            oserror_path(2, "/x/y"),
            "[Errno 2] No such file or directory: '/x/y'"
        );
        assert_eq!(
            oserror_path(13, "/it's"),
            "[Errno 13] Permission denied: \"/it's\""
        );
    }

    #[test]
    fn py_repr_quotes_and_escapes_like_python() {
        for (s, want) in [
            ("x", "'x'"),
            ("", "''"),
            ("it's", "\"it's\""),
            ("a\"b", "'a\"b'"),
            ("'\"", "'\\'\"'"),
            ("a\\b", "'a\\\\b'"),
            ("a\nb\rc\td", "'a\\nb\\rc\\td'"),
            ("\x01\x7f", "'\\x01\\x7f'"),
            ("é", "'é'"),
        ] {
            assert_eq!(py_repr(s), want, "{s:?}");
        }
    }

    #[test]
    fn non_finite_floats_print_like_json_dumps() {
        assert_eq!(float_json(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(float_json(f64::NAN), "NaN");
        assert_eq!(float_repr(f64::INFINITY), "inf");
        assert_eq!(float_repr(f64::NEG_INFINITY), "-inf");
        assert_eq!(float_repr(-0.0), "-0.0");
        assert_eq!(float_repr(0.0), "0.0");
        assert_eq!(float_repr(-1.5e-7), "-1.5e-07");
        assert_eq!(float_repr(1e22), "1e+22");
    }

    #[test]
    fn safe_escapes_the_first_non_ascii_control_and_del() {
        assert_eq!(safe_str("\u{7f}"), "\\x7f");
        assert_eq!(safe_str("\u{80}"), "\\x80");
        assert_eq!(safe_str("\u{a0}"), "\\xa0");
        assert_eq!(safe_str("\u{a1}"), "¡");
    }
}
