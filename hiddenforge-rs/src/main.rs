//! HiddenForge 3.0 in-image runtime: one multi-call binary.
//!
//! Started with no arguments (or unknown ones) it is PID 1, the supervisor.
//! Its other names and arguments are the healthcheck, the upload watcher, the
//! guards, the operator commands and the 2.x compatibility forms.
mod fsops;
mod guards;
mod health;
mod privs;
mod py;
mod supervisor;
mod torrc;

use py::Json;
use std::time::Duration;

fn torrc_preview() -> i32 {
    let env = torrc::python_environ();
    let t = torrc::build(&env, &torrc::libc_resolve);
    let strs = |v: &[String]| Json::Arr(v.iter().map(|s| Json::Str(s.clone())).collect());
    let doc = Json::obj()
        .with("content", t.content.clone().into())
        .with("hs_dirs", strs(&t.hs_dirs))
        .with("dropped", strs(&t.dropped))
        .with("resolved", Json::Obj(t.resolved.iter().map(|(k, v)| (k.clone(), Json::Str(v.clone()))).collect()))
        .with("unresolved", strs(&t.unresolved))
        .with("log", strs(&t.log));
    println!("{}", py::dumps(&doc, false, None));
    0
}

fn is_socket(path: &str) -> i32 {
    match fsops::lstat(path) {
        Ok(st) if fsops::is_type(&st, libc::S_IFSOCK) => 0,
        _ => 1,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args.first().map(|a| a.rsplit('/').next().unwrap_or("").to_string()).unwrap_or_default();
    if argv0 == health::GUARDS_ARGV0 {
        std::process::exit(guards::main(&args[1..]));
    }
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let code = match rest.as_slice() {
        ["torrc-preview"] => torrc_preview(),
        ["__true"] => 0,
        ["__is-socket", p] => is_socket(p),
        ["healthcheck", "--watch-uploads"] => {
            health::watch_uploads(health::UPLOADS_FILE, health::CONTROL_SOCKET, Duration::from_secs(60))
        }
        ["healthcheck", "--json"] => health::main_check(true),
        ["healthcheck"] => health::main_check(false),
        _ => supervisor::run(),
    };
    std::process::exit(code);
}
