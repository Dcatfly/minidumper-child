use std::{
    ffi::{OsStr, OsString},
    io::Write,
    panic::{self, AssertUnwindSafe},
    path::{Path, PathBuf},
    process,
    sync::Arc,
    time::Duration,
};

pub mod client;
pub mod server;
#[doc(hidden)]
pub mod socket_dir;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid socket name: {0:?}")]
    InvalidSocketName(OsString),
    #[error("Failed to spawn process")]
    SpawnProcess(#[source] std::io::Error),
    #[error("Failed to attach crash handler")]
    AttachCrashHandler(#[source] crash_handler::Error),
    #[error("Faled to send message")]
    SendMessage(#[source] minidumper::Error),
    #[error("Failed to create client with socket name {socket_name:?}")]
    CreateClient {
        #[source]
        source: minidumper::Error,
        socket_name: OwnedSocketName,
    },
    #[error("Failed to create server with socket name {socket_name:?}")]
    CreateServer {
        #[source]
        source: minidumper::Error,
        socket_name: OwnedSocketName,
    },
    #[error("Error while running server")]
    RunServer(#[source] minidumper::Error),
}

pub struct ClientHandle {
    client: Arc<minidumper::Client>,
    _handler: crash_handler::CrashHandler,
    _child: process::Child,
}

impl ClientHandle {
    pub fn send_message(&self, kind: u32, buf: impl AsRef<[u8]>) -> Result<(), Error> {
        self.client
            .send_message(kind, buf)
            .map_err(Error::SendMessage)
    }
}

pub type OnProcess = Box<dyn FnOnce(&mut process::Command) + Send + Sync + 'static>;
pub type OnMinidump = Box<dyn Fn(Vec<u8>, &Path) + Send + Sync + 'static>;
pub type OnMessage = Box<dyn Fn(u32, Vec<u8>) + Send + Sync + 'static>;

pub struct MinidumperChild {
    crashes_dir: PathBuf,
    server_stale_timeout: Duration,
    client_connect_timeout: Duration,
    server_connect_timeout: Option<Duration>,
    server_env: String,
    on_process: Option<OnProcess>,
    on_minidump: Option<OnMinidump>,
    on_message: Option<OnMessage>,
}

/// The default for [`MinidumperChild::with_client_connect_timeout`].
const DEFAULT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_millis(3000);

impl Default for MinidumperChild {
    fn default() -> Self {
        Self {
            crashes_dir: std::env::temp_dir().join("Crashes"),
            server_stale_timeout: Duration::from_millis(5000),
            client_connect_timeout: DEFAULT_CLIENT_CONNECT_TIMEOUT,
            server_connect_timeout: None,
            server_env: "_CRASH_REPORTER_SERVER".to_owned(),
            on_process: None,
            on_minidump: None,
            on_message: None,
        }
    }
}

impl MinidumperChild {
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether the current process is the crash reporting server process.
    pub fn is_crash_reporter_process(&self) -> bool {
        std::env::var_os(&self.server_env).is_some()
    }

    /// Configures a callback which can be used to modify the server process.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn on_process<F>(mut self, on_process: F) -> Self
    where
        F: FnOnce(&mut process::Command) + Send + Sync + 'static,
    {
        self.on_process = Some(Box::new(on_process));
        self
    }

    /// Configures a callback which is invoked with the generated minidump on crash.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn on_minidump<F>(mut self, on_minidump: F) -> Self
    where
        F: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    {
        self.on_minidump = Some(Box::new(on_minidump));
        self
    }

    /// Configures a callback which is invoked with messages from the app process.
    ///
    /// A message may be sent using [`ClientHandle::send_message`].
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn on_message<F>(mut self, on_message: F) -> Self
    where
        F: Fn(u32, Vec<u8>) + Send + Sync + 'static,
    {
        self.on_message = Some(Box::new(on_message));
        self
    }

    /// Configures the directory where crash dumps will be stored.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn with_crashes_dir(mut self, crashes_dir: PathBuf) -> Self {
        self.crashes_dir = crashes_dir;
        self
    }

    /// Configures the server stale timeout.
    ///
    /// The server expects periodic messages from the client process, if it does not receive
    /// a message within `timeout`, it considers the connection broken and detach.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn with_server_stale_timeout(mut self, timeout: Duration) -> Self {
        self.server_stale_timeout = timeout;
        self
    }

    /// Configures the client connect timeout.
    ///
    /// This is the amount of time the client will wait to establish a connection to the server.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn with_client_connect_timeout(mut self, timeout: Duration) -> Self {
        self.client_connect_timeout = timeout;
        self
    }

    /// Configures how long the server process waits for the first client connection.
    ///
    /// If no client has connected within this time the server process exits on its own,
    /// so it can't be left behind when the app process fails to connect or dies before
    /// connecting.
    ///
    /// The value must be more than one second longer than the client connect timeout (see
    /// [`MinidumperChild::with_client_connect_timeout`]) so that a client that is slow to
    /// connect, but still within its own timeout, isn't cut off. Other values are ignored
    /// and the default is used instead.
    ///
    /// Defaults to twice the client connect timeout, and at least one second more than it.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn with_server_connect_timeout(mut self, timeout: Duration) -> Self {
        self.server_connect_timeout = Some(timeout);
        self
    }

    /// Configures the name of an environment variable which is passed to the server process.
    ///
    /// This defaults to `_CRASH_REPORTER_SERVER`.
    #[must_use = "You should call spawn() or the crash reporter won't be enabled"]
    pub fn with_server_env_var(mut self, name: String) -> Self {
        self.server_env = name;
        self
    }

    #[must_use = "The return value of spawn() should not be dropped until the program exits"]
    pub fn spawn(self) -> Result<ClientHandle, Error> {
        if self.on_minidump.is_none() && self.on_message.is_none() {
            panic!("You should set one of 'on_minidump' or 'on_message'");
        }

        if let Some(socket_name) = std::env::var_os(&self.server_env) {
            // This is the crash reporter process. It must never return to the caller,
            // otherwise the app code after `spawn()` would run in the crash reporter
            // process too, so every outcome ends in an explicit exit.
            //
            // Panics, e.g. from the `on_minidump` or `on_message` callbacks, are caught so
            // they don't unwind into the caller either. The panic hook still runs first,
            // and this has no effect when built with `panic = "abort"`.
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                let socket_name = OwnedSocketName::from_os_str(&socket_name)
                    .ok_or_else(|| Error::InvalidSocketName(socket_name.clone()))?;

                let connect_grace =
                    server_connect_grace(self.client_connect_timeout, self.server_connect_timeout);

                server::start_with_connect_grace(
                    socket_name,
                    self.crashes_dir,
                    self.server_stale_timeout,
                    connect_grace,
                    self.on_minidump,
                    self.on_message,
                )
            }));

            let code = match result {
                Ok(Ok(())) => 0,
                Ok(Err(err)) => {
                    write_error(&err);
                    1
                }
                Err(_) => 1,
            };

            std::process::exit(code);
        } else {
            // We use a unique socket name because we don't share the crash reporter
            // processes between different instances of the app.
            let socket_name = app_socket_name();

            let mut server_process = std::env::current_exe()
                .and_then(|current_exe| {
                    let mut process = process::Command::new(current_exe);
                    if let Some(on_process) = self.on_process {
                        on_process(&mut process);
                    }
                    // Always set this last, so an accidental `env_clear()` doesn't remove it.
                    process.env(self.server_env, socket_name.as_os_string());
                    process.spawn()
                })
                .map_err(Error::SpawnProcess)?;

            match client::start(
                socket_name.clone(),
                self.client_connect_timeout,
                server_process.id(),
                self.server_stale_timeout / 2,
            ) {
                Ok((client, handler)) => Ok(ClientHandle {
                    client,
                    _handler: handler,
                    _child: server_process,
                }),
                Err(err) => {
                    // Without a connected client and an attached crash handler the server
                    // process is useless, and it would never exit on its own if no client
                    // ever connected, so make sure it doesn't outlive this call.
                    terminate_server(&mut server_process, &socket_name);
                    Err(err)
                }
            }
        }
    }
}

/// Writes an error and its sources to stderr.
///
/// Unlike `eprintln!` this doesn't panic if stderr is closed.
fn write_error(err: &dyn std::error::Error) {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        message.push_str(": ");
        message.push_str(&err.to_string());
        source = err.source();
    }

    let _ = writeln!(std::io::stderr(), "{message}");
}

/// Kills the server process, waits for it to exit and removes its socket file.
///
/// This is best effort: errors are ignored because the caller is already returning an error.
fn terminate_server(server_process: &mut process::Child, socket_name: &OwnedSocketName) {
    let _ = server_process.kill();
    let _ = server_process.wait();

    // A killed server doesn't get to remove its socket file
    match socket_name {
        OwnedSocketName::Path(path) => {
            let _ = std::fs::remove_file(path);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        OwnedSocketName::Abstract(_) => {}
    }
}

/// Returns a new socket name for the app process to pass to the server process.
///
/// Packaged apps on Windows use a location inside the package where connecting works,
/// everything else uses the system temporary directory.
#[doc(hidden)]
pub fn app_socket_name() -> OwnedSocketName {
    let session_id = uuid::Uuid::new_v4();

    #[cfg(windows)]
    if let Some(socket_name) = socket_dir::sys::packaged_socket_name(session_id) {
        return socket_name;
    }

    OwnedSocketName::new(&std::env::temp_dir(), session_id)
}

/// The minimum amount by which the server connect grace period exceeds the client connect
/// timeout.
const MIN_SERVER_CONNECT_MARGIN: Duration = Duration::from_secs(1);

/// Returns how long the server waits for the first client before exiting on its own.
///
/// The result is always at least [`MIN_SERVER_CONNECT_MARGIN`] longer than
/// `client_connect_timeout`. The client starts its timer before the server process is
/// spawned, while the server starts its timer after binding the socket, so the server only
/// gives up on a client that is still trying to connect if the client overshoots its own
/// timeout by more than the margin. That can happen because the client timeout only counts
/// the time slept between attempts, not the time spent in each attempt, but should not in
/// practice.
///
/// The default is twice the client timeout, and at least the margin more than it for short
/// timeouts. A `configured` value is used as-is if it is more than the margin longer than
/// the client timeout, otherwise the default is used instead.
fn server_connect_grace(
    client_connect_timeout: Duration,
    configured: Option<Duration>,
) -> Duration {
    let minimum = client_connect_timeout.saturating_add(MIN_SERVER_CONNECT_MARGIN);

    match configured {
        Some(configured) if configured > minimum => configured,
        _ => client_connect_timeout.saturating_mul(2).max(minimum),
    }
}

/// An owned version of [SocketName](minidumper::SocketName).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnedSocketName {
    Path(PathBuf),
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Abstract(String),
}

impl OwnedSocketName {
    const PATH_PREFIX: &str = "path:";
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ABSTRACT_PREFIX: &str = "abstract:";

    fn new(base_dir: &Path, session_id: uuid::Uuid) -> Self {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            return Self::Abstract(format!("temp-socket-{}", session_id.simple()));
        }

        let mut path = base_dir.to_path_buf();
        path.push(format!("temp-socket-{}", session_id.simple()));
        Self::Path(path)
    }

    fn as_ref(&self) -> minidumper::SocketName<'_> {
        match self {
            Self::Path(p) => minidumper::SocketName::Path(p.as_path()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Abstract(s) => minidumper::SocketName::Abstract(s.as_str()),
        }
    }

    fn as_os_string(&self) -> OsString {
        match self {
            Self::Path(p) => {
                let mut out = OsString::from(Self::PATH_PREFIX.to_string());
                out.push(p);
                out
            }

            #[cfg(any(target_os = "linux", target_os = "android"))]
            Self::Abstract(s) => {
                let mut out = OsString::from(Self::ABSTRACT_PREFIX.to_string());
                out.push(s);
                out
            }
        }
    }

    fn from_os_str(os_str: &OsStr) -> Option<Self> {
        let strip_prefix = |prefix: &OsStr| -> Option<&OsStr> {
            let rest = os_str
                .as_encoded_bytes()
                .strip_prefix(prefix.as_encoded_bytes())?;
            // SAFETY: The bytes we are passing in were originally an `OsStr`. We only
            // stripped off a prefix that was also an `OsStr`.
            unsafe { Some(OsStr::from_encoded_bytes_unchecked(rest)) }
        };

        let path_prefix: &OsStr = OsStr::new(Self::PATH_PREFIX);

        if let Some(path) = strip_prefix(path_prefix) {
            return Some(Self::Path(PathBuf::from(path)));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let abstract_prefix: &OsStr = OsStr::new(Self::ABSTRACT_PREFIX);

            if let Some(name) = strip_prefix(abstract_prefix) {
                let name = name.to_str()?.to_owned();
                return Some(Self::Abstract(name));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::time::Duration;

    use uuid::Uuid;

    use crate::{
        app_socket_name, server_connect_grace, OwnedSocketName, MIN_SERVER_CONNECT_MARGIN,
    };

    #[test]
    fn owned_socket_name_roundtrip_new() {
        let sn = OwnedSocketName::new("/tmp".as_ref(), Uuid::new_v4());
        let os_str = sn.as_os_string();
        assert_eq!(OwnedSocketName::from_os_str(&os_str).unwrap(), sn);
    }

    #[test]
    fn owned_socket_name_roundtrip_path_utf8() {
        let sn = OwnedSocketName::Path("/tmp/mysocket".into());
        let os_str = sn.as_os_string();
        assert_eq!(OwnedSocketName::from_os_str(&os_str).unwrap(), sn);
    }

    #[cfg(unix)]
    #[test]
    fn owned_socket_name_roundtrip_path_unix() {
        use std::os::unix::ffi::OsStrExt;
        // Example of a non-UTF-8 path from stdlib docs:
        // Here, the values 0x66 and 0x6f correspond to 'f' and 'o'
        // respectively. The value 0x80 is a lone continuation byte, invalid
        // in a UTF-8 sequence.
        let source = [0x66, 0x6f, 0x80, 0x6f];
        let path = OsStr::from_bytes(&source[..]);
        let sn = OwnedSocketName::Path(PathBuf::from(path));
        let os_str = sn.as_os_string();
        assert_eq!(OwnedSocketName::from_os_str(&os_str).unwrap(), sn);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn owned_socket_name_roundtrip_abstract() {
        let sn = OwnedSocketName::Abstract("my-tmp-socket".into());
        let os_str = sn.as_os_string();
        assert_eq!(OwnedSocketName::from_os_str(&os_str).unwrap(), sn);
    }

    #[test]
    fn server_connect_grace_defaults_to_twice_the_connect_timeout() {
        let grace = server_connect_grace(Duration::from_secs(3), None);
        assert_eq!(grace, Duration::from_secs(6));
    }

    #[test]
    fn server_connect_grace_default_keeps_a_margin_for_short_timeouts() {
        assert_eq!(
            server_connect_grace(Duration::from_millis(500), None),
            Duration::from_millis(1500)
        );
        assert_eq!(
            server_connect_grace(Duration::ZERO, None),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn server_connect_grace_uses_configured_value_greater_than_minimum() {
        let grace = server_connect_grace(Duration::from_secs(3), Some(Duration::from_secs(5)));
        assert_eq!(grace, Duration::from_secs(5));

        let just_over = Duration::from_secs(4) + Duration::from_nanos(1);
        let grace = server_connect_grace(Duration::from_secs(3), Some(just_over));
        assert_eq!(grace, just_over);
    }

    #[test]
    fn server_connect_grace_replaces_configured_value_not_greater_than_minimum() {
        let connect = Duration::from_secs(3);

        // Anything up to and including the connect timeout plus the margin is replaced
        for configured in [
            Duration::ZERO,
            Duration::from_secs(1),
            connect,
            connect + Duration::from_millis(500),
            connect + MIN_SERVER_CONNECT_MARGIN,
        ] {
            let grace = server_connect_grace(connect, Some(configured));
            assert_eq!(
                grace,
                Duration::from_secs(6),
                "{configured:?} was not replaced"
            );
        }
    }

    #[test]
    fn server_connect_grace_always_exceeds_connect_timeout_by_margin() {
        for millis in [0, 1, 50, 999, 1000, 3000, 60_000] {
            let connect = Duration::from_millis(millis);
            for configured in [None, Some(Duration::ZERO), Some(connect)] {
                let grace = server_connect_grace(connect, configured);
                assert!(grace >= connect + MIN_SERVER_CONNECT_MARGIN, "{connect:?}");
            }
        }
    }

    /// A server handler that doesn't do anything.
    struct NoopHandler;

    impl minidumper::ServerHandler for NoopHandler {
        fn create_minidump_file(&self) -> Result<(std::fs::File, PathBuf), std::io::Error> {
            Err(std::io::Error::other("not supported"))
        }

        fn on_minidump_created(
            &self,
            _result: Result<minidumper::MinidumpBinary, minidumper::Error>,
        ) -> minidumper::LoopAction {
            minidumper::LoopAction::Exit
        }

        fn on_message(&self, _kind: u32, _buffer: Vec<u8>) {}
    }

    #[test]
    fn app_socket_name_accepts_connections() {
        use std::sync::{atomic::AtomicBool, mpsc, Arc};

        let socket_name = app_socket_name();

        // The client waits for the server to answer on some platforms, so the server has to
        // run. Both run on their own threads so a hang fails the test rather than blocking it.
        let mut server = minidumper::Server::with_name(socket_name.as_ref()).expect("should bind");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_thread = std::thread::spawn({
            let shutdown = shutdown.clone();
            move || {
                let result = server.run(Box::new(NoopHandler), &shutdown, None);
                // Dropping the server removes the socket file
                drop(server);
                result.map_err(|err| err.to_string())
            }
        });

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn({
            let socket_name = socket_name.clone();
            move || {
                let result = minidumper::Client::with_name(socket_name.as_ref())
                    .map(drop)
                    .map_err(|err| err.to_string());
                let _ = sender.send(result);
            }
        });
        let connected = receiver.recv_timeout(Duration::from_secs(10));

        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        let server_result = server_thread.join().expect("server thread panicked");

        assert_eq!(
            connected,
            Ok(Ok(())),
            "client should connect to {socket_name:?}"
        );
        assert_eq!(server_result, Ok(()));
        match &socket_name {
            OwnedSocketName::Path(path) => assert!(!path.exists()),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            OwnedSocketName::Abstract(_) => {}
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn app_socket_name_is_unchanged_outside_windows() {
        match app_socket_name() {
            OwnedSocketName::Path(path) => {
                assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
                let name = path.file_name().unwrap().to_str().unwrap();
                assert!(name.starts_with("temp-socket-"), "{name}");
                assert_eq!(name.len(), "temp-socket-".len() + 32);
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            OwnedSocketName::Abstract(name) => {
                assert!(name.starts_with("temp-socket-"), "{name}");
                assert_eq!(name.len(), "temp-socket-".len() + 32);
            }
        }
    }
}
