//! Example used by `tests/lifecycle.rs` to check that the crash reporter process never
//! outlives a failed `spawn()`. It is configured through environment variables:
//!
//! - `LIFECYCLE_CONNECT_TIMEOUT_MS`: client connect timeout
//! - `LIFECYCLE_SERVER_CONNECT_TIMEOUT_MS`: server connect timeout
//! - `LIFECYCLE_STUB_REPORT`: when set in the app process, the crash reporter process is
//!   replaced by a stub that never serves, see [`run_stub_server`]
use std::{
    env, fs,
    path::PathBuf,
    process::{self, Stdio},
    time::Duration,
};

use minidumper_child::MinidumperChild;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const SERVER_ENV: &str = "_CRASH_REPORTER_SERVER";
/// Only ever set on the crash reporter process, via `on_process`
const STUB_SERVER_ENV: &str = "LIFECYCLE_STUB_SERVER";
const STUB_REPORT_ENV: &str = "LIFECYCLE_STUB_REPORT";

fn env_millis(name: &str) -> Option<Duration> {
    let value = env::var(name).ok()?;
    Some(Duration::from_millis(
        value.parse().expect("invalid duration"),
    ))
}

/// Pretends to be a crash reporter process whose socket can't be connected to.
///
/// Like a server whose socket the client can't open, it leaves a file at the socket path,
/// so the test can check that a failed `spawn()` removes it. It then writes its pid and the
/// socket path to the report file and sleeps until it is killed. The report also includes the
/// process start time, so the test can tell this process from one that reused its pid.
fn run_stub_server() -> ! {
    let socket_name = env::var(SERVER_ENV).expect("socket name should be valid UTF-8");

    // On Linux and Android the socket is abstract, so there is no file to leave behind
    let socket_path = socket_name.strip_prefix("path:").map(PathBuf::from);
    if let Some(socket_path) = &socket_path {
        fs::write(socket_path, b"not a socket").expect("failed to create socket file");
    }

    let socket_path = socket_path
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let pid = process::id();
    let mut system = System::new();
    let sys_pid = Pid::from_u32(pid);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[sys_pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    let start_time = system
        .process(sys_pid)
        .expect("should find own process")
        .start_time();

    // Write to a temporary file first so the test never reads a partial report
    let report = PathBuf::from(env::var_os(STUB_REPORT_ENV).expect("report path should be set"));
    let partial = report.with_extension("partial");
    fs::write(&partial, format!("{pid}\n{start_time}\n{socket_path}"))
        .expect("failed to write report");
    fs::rename(&partial, &report).expect("failed to write report");

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn main() {
    if env::var_os(SERVER_ENV).is_some() && env::var_os(STUB_SERVER_ENV).is_some() {
        run_stub_server();
    }

    let mut reporter = MinidumperChild::new().on_minidump(|_buffer, _path| {});

    if let Some(timeout) = env_millis("LIFECYCLE_CONNECT_TIMEOUT_MS") {
        reporter = reporter.with_client_connect_timeout(timeout);
    }

    if let Some(timeout) = env_millis("LIFECYCLE_SERVER_CONNECT_TIMEOUT_MS") {
        reporter = reporter.with_server_connect_timeout(timeout);
    }

    if env::var_os(STUB_REPORT_ENV).is_some() {
        reporter = reporter.on_process(|command| {
            // The stub never writes to stdout, and must not hold the test's stdout pipe open
            command.env(STUB_SERVER_ENV, "1").stdout(Stdio::null());
        });
    }

    println!("SERVER_STARTING");

    let result = reporter.spawn();

    // Only the app process should ever get here
    println!("APP_CODE_RAN");

    match result {
        Ok(_handle) => println!("SPAWN_OK"),
        Err(err) => println!("SPAWN_ERR {err:?}"),
    }
}
