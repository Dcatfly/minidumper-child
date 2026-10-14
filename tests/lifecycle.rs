//! Checks that the crash reporter process doesn't outlive the app process on failure paths.
use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{mpsc, Once},
    thread,
    time::{Duration, Instant},
};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const SERVER_ENV: &str = "_CRASH_REPORTER_SERVER";

/// A unique temporary directory, removed on drop.
///
/// The name is kept short because socket paths are limited to ~100 bytes.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = env::temp_dir().join(format!("mdct-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cargo() -> Command {
    Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

/// Builds the example up front so that compiling it doesn't eat into any timeouts.
fn build_example() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let status = cargo()
            .args(["build", "--example", "lifecycle"])
            .status()
            .expect("failed to run cargo build");
        assert!(status.success(), "failed to build lifecycle example");
    });
}

fn example() -> Command {
    build_example();
    let mut command = cargo();
    command
        .args(["run", "--quiet", "--example", "lifecycle"])
        .env_remove(SERVER_ENV)
        .stdout(Stdio::piped());
    command
}

/// Returns the start time of the process with `pid`, if it is running.
fn process_start_time(pid: u32) -> Option<u64> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system.process(pid).map(|process| process.start_time())
}

/// Kills the process with `pid` if it is running and was started at `start_time`.
fn kill_process(pid: u32, start_time: u64) {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    if let Some(process) = system.process(pid) {
        if process.start_time() == start_time {
            process.kill();
        }
    }
}

/// A running example whose stdout lines are timestamped as they arrive.
struct Running {
    child: Child,
    lines: mpsc::Receiver<(String, Instant)>,
    seen: Vec<String>,
}

impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command.spawn().expect("failed to spawn example");
        let stdout = child.stdout.take().expect("stdout should be piped");
        let (sender, lines) = mpsc::channel();

        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send((line, Instant::now())).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Waits for a line from the example and returns when it was received.
    fn wait_for_line(&mut self, expected: &str, timeout: Duration) -> Instant {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(remaining) {
                Ok((line, at)) => {
                    let found = line == expected;
                    self.seen.push(line);
                    if found {
                        return at;
                    }
                }
                Err(_) => {
                    let _ = self.child.kill();
                    panic!("didn't receive {expected:?}, got {:?}", self.seen);
                }
            }
        }
    }

    /// Waits for the example to exit, killing it and failing if it doesn't exit in time.
    fn wait_for_exit(&mut self, timeout: Duration) -> (ExitStatus, Instant) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("failed to wait for example") {
                return (status, Instant::now());
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("example didn't exit within {timeout:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Returns all stdout lines. Only call after the example has exited.
    fn output(mut self) -> Vec<String> {
        while let Ok((line, _)) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(line);
        }
        self.seen
    }
}

#[test]
fn client_connect_failure_terminates_server_process() {
    // Make sure that `process_start_time` can actually see a live process
    assert!(process_start_time(std::process::id()).is_some());

    let dir = TempDir::new("conn");
    let report = dir.0.join("report");

    let mut command = example();
    command
        .env("LIFECYCLE_CONNECT_TIMEOUT_MS", "4000")
        .env("LIFECYCLE_STUB_REPORT", &report);

    // Use a timeout rather than waiting for stdout to close: on Windows the server process
    // may inherit the stdout pipe, so a server that isn't terminated would hang the test.
    let mut running = Running::spawn(command);
    let (status, _) = running.wait_for_exit(Duration::from_secs(120));
    let stdout = running.output();

    assert!(status.success(), "example failed: {stdout:?}");
    assert!(
        stdout
            .iter()
            .any(|line| line.starts_with("SPAWN_ERR CreateClient")),
        "spawn() should fail to connect: {stdout:?}"
    );

    // The stub server writes the report after creating the file at its socket path, so
    // this also proves that the file existed
    let report = fs::read_to_string(&report).expect("stub server should have written a report");
    let mut report = report.splitn(3, '\n');
    let pid: u32 = report.next().unwrap().parse().expect("malformed pid");
    let start_time: u64 = report
        .next()
        .expect("missing start time")
        .parse()
        .expect("malformed start time");
    let socket_path = report.next().expect("missing socket path");

    // A process with the same pid but a different start time is an unrelated process
    let alive = process_start_time(pid) == Some(start_time);
    if alive {
        kill_process(pid, start_time);
    }
    let socket_exists = !socket_path.is_empty() && Path::new(socket_path).exists();
    if socket_exists {
        let _ = fs::remove_file(socket_path);
    }

    assert!(!alive, "server process {pid} is still running");

    // Linux and Android use abstract sockets which don't have a file
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        assert!(!socket_path.is_empty(), "socket should be a path");
        assert!(!socket_exists, "socket file {socket_path} was not removed");
    }
}

/// Runs the example as a server that no client ever connects to.
///
/// Returns the exit status and how long the server ran for.
fn run_unconnected_server(
    name: &str,
    client_connect_timeout_ms: u64,
    server_connect_timeout_ms: u64,
) -> (ExitStatus, Duration, Vec<String>) {
    let dir = TempDir::new(name);
    let socket = dir.0.join("s");

    let mut command = example();
    command
        .env(SERVER_ENV, format!("path:{}", socket.display()))
        .env(
            "LIFECYCLE_CONNECT_TIMEOUT_MS",
            client_connect_timeout_ms.to_string(),
        )
        .env(
            "LIFECYCLE_SERVER_CONNECT_TIMEOUT_MS",
            server_connect_timeout_ms.to_string(),
        );

    let mut running = Running::spawn(command);
    let started = running.wait_for_line("SERVER_STARTING", Duration::from_secs(120));

    // Make sure the socket file was created, so checking that it was removed means something
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(
            running.child.try_wait().unwrap().is_none(),
            "server exited before creating its socket"
        );
        assert!(Instant::now() < deadline, "socket was never created");
        thread::sleep(Duration::from_millis(10));
    }

    let longest = client_connect_timeout_ms.max(server_connect_timeout_ms) * 2;
    let (status, exited) =
        running.wait_for_exit(Duration::from_millis(longest) + Duration::from_secs(10));

    assert!(!socket.exists(), "socket file was not removed");

    (status, exited - started, running.output())
}

#[test]
fn server_exits_when_no_client_connects() {
    let (status, ran_for, output) = run_unconnected_server("idle", 500, 2500);

    assert_eq!(status.code(), Some(0), "output: {output:?}");
    assert!(
        ran_for >= Duration::from_millis(2500),
        "server exited after {ran_for:?}, before its connect timeout"
    );
    assert!(
        ran_for < Duration::from_millis(2500) + Duration::from_secs(5),
        "server took {ran_for:?} to exit"
    );
    assert!(!output.iter().any(|line| line == "APP_CODE_RAN"));
}

#[test]
fn server_waits_longer_than_client_connect_timeout() {
    // A server connect timeout shorter than the client connect timeout is not honoured,
    // the server waits at least one second longer than the client
    let (status, ran_for, output) = run_unconnected_server("wait", 2000, 100);

    assert_eq!(status.code(), Some(0), "output: {output:?}");
    assert!(
        ran_for >= Duration::from_millis(3000),
        "server exited after {ran_for:?}, too soon after the client connect timeout"
    );
    assert!(!output.iter().any(|line| line == "APP_CODE_RAN"));
}

/// Runs the example as a server with the given socket name, which should fail to start.
fn run_failing_server(socket_name: &str) -> (ExitStatus, Vec<String>) {
    let mut command = example();
    command.env(SERVER_ENV, socket_name);

    let mut running = Running::spawn(command);
    running.wait_for_line("SERVER_STARTING", Duration::from_secs(120));
    let (status, _) = running.wait_for_exit(Duration::from_secs(30));
    (status, running.output())
}

#[test]
fn server_start_failure_exits_crash_reporter_process() {
    let dir = TempDir::new("fail");
    let socket = dir.0.join("missing").join("s");

    let (status, output) = run_failing_server(&format!("path:{}", socket.display()));

    assert_eq!(status.code(), Some(1), "output: {output:?}");
    assert!(
        !output.iter().any(|line| line == "APP_CODE_RAN"),
        "app code ran in the crash reporter process: {output:?}"
    );
}

#[test]
fn invalid_socket_name_exits_crash_reporter_process() {
    let (status, output) = run_failing_server("not-a-socket-name");

    assert_eq!(status.code(), Some(1), "output: {output:?}");
    assert!(
        !output.iter().any(|line| line == "APP_CODE_RAN"),
        "app code ran in the crash reporter process: {output:?}"
    );
}
