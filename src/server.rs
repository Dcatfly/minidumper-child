use minidumper::{LoopAction, MinidumpBinary, Server, ServerHandler};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{Error, OwnedSocketName};

struct Handler<Minidump, Message>
where
    Minidump: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    Message: Fn(u32, Vec<u8>) + Send + Sync + 'static,
{
    crashes_dir: PathBuf,
    /// Set once a client has connected, read by the connect watchdog
    connected: Arc<AtomicBool>,
    on_minidump: Option<Minidump>,
    on_message: Option<Message>,
}

impl<Minidump, Message> Handler<Minidump, Message>
where
    Minidump: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    Message: Fn(u32, Vec<u8>) + Send + Sync + 'static,
{
    pub fn new(
        crashes_dir: PathBuf,
        connected: Arc<AtomicBool>,
        on_minidump: Option<Minidump>,
        on_message: Option<Message>,
    ) -> Self {
        Handler {
            crashes_dir,
            connected,
            on_minidump,
            on_message,
        }
    }
}

impl<Minidump, Message> ServerHandler for Handler<Minidump, Message>
where
    Minidump: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    Message: Fn(u32, Vec<u8>) + Send + Sync + 'static,
{
    /// Called when a crash has been received and a backing file needs to be
    /// created to store it.
    fn create_minidump_file(&self) -> Result<(File, PathBuf), io::Error> {
        fs::create_dir_all(&self.crashes_dir)?;
        let file_name = format!("{}.dmp", uuid::Uuid::new_v4());
        let path = self.crashes_dir.join(file_name);
        Ok((File::create(&path)?, path))
    }

    /// Called when a crash has been fully written as a minidump to the provided
    /// file. Also returns the full heap buffer as well.
    fn on_minidump_created(&self, result: Result<MinidumpBinary, minidumper::Error>) -> LoopAction {
        if let Ok(mut minidump) = result {
            if let Some(buffer) = minidump.contents.or_else(|| {
                minidump.file.flush().ok().and_then(|_| {
                    let mut buf = Vec::new();
                    File::open(&minidump.path)
                        .unwrap()
                        .read_to_end(&mut buf)
                        .map(|_| buf)
                        .ok()
                })
            }) {
                if let Some(on_minidump) = &self.on_minidump {
                    on_minidump(buffer, &minidump.path)
                }
            }

            fs::remove_file(minidump.path).ok();
        }

        // Tells the server to exit, which will in turn exit the process
        LoopAction::Exit
    }

    fn on_message(&self, kind: u32, buffer: Vec<u8>) {
        if let Some(on_message) = &self.on_message {
            on_message(kind, buffer);
        }
    }

    fn on_client_connected(&self, _num_clients: usize) -> minidumper::LoopAction {
        self.connected.store(true, Ordering::SeqCst);
        LoopAction::Continue
    }

    fn on_client_disconnected(&self, _num_clients: usize) -> minidumper::LoopAction {
        LoopAction::Exit
    }
}

/// Exits the server loop if no client has connected within `grace`.
///
/// Once a client has connected, the stale timeout and the disconnect handler take care of
/// exiting the server, but they never fire if no client ever connects. Without this the
/// server process would run forever, e.g. when the client fails to connect or the app
/// process dies before connecting.
fn spawn_connect_watchdog(grace: Duration, connected: Arc<AtomicBool>, shutdown: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        std::thread::sleep(grace);

        if !connected.load(Ordering::SeqCst) {
            shutdown.store(true, Ordering::SeqCst);
        }
    });
}

/// Runs the server until the client disconnects or crashes.
///
/// Exits if no client connects within the grace period derived from the default client
/// connect timeout. See [`start_with_connect_grace`] to configure it.
pub fn start<Minidump, Message>(
    socket_name: OwnedSocketName,
    crashes_dir: PathBuf,
    stale_timeout: Duration,
    on_minidump: Option<Minidump>,
    on_message: Option<Message>,
) -> Result<(), Error>
where
    Minidump: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    Message: Fn(u32, Vec<u8>) + Send + Sync + 'static,
{
    start_with_connect_grace(
        socket_name,
        crashes_dir,
        stale_timeout,
        crate::server_connect_grace(crate::DEFAULT_CLIENT_CONNECT_TIMEOUT, None),
        on_minidump,
        on_message,
    )
}

/// Runs the server until the client disconnects or crashes, or until `connect_grace` has
/// passed without a client connecting.
pub fn start_with_connect_grace<Minidump, Message>(
    socket_name: OwnedSocketName,
    crashes_dir: PathBuf,
    stale_timeout: Duration,
    connect_grace: Duration,
    on_minidump: Option<Minidump>,
    on_message: Option<Message>,
) -> Result<(), Error>
where
    Minidump: Fn(Vec<u8>, &Path) + Send + Sync + 'static,
    Message: Fn(u32, Vec<u8>) + Send + Sync + 'static,
{
    // The server is dropped before returning, which removes its socket file. This has to
    // happen here because the caller exits the process, which doesn't run destructors.
    Server::with_name(socket_name.as_ref())
        .map_err(|err| Error::CreateServer {
            source: err,
            socket_name,
        })
        .and_then(|mut server| {
            let connected = Arc::new(AtomicBool::new(false));
            let shutdown = Arc::new(AtomicBool::new(false));

            // The grace period starts once the socket is bound
            spawn_connect_watchdog(connect_grace, connected.clone(), shutdown.clone());

            let handler = Box::new(Handler::new(
                crashes_dir,
                connected,
                on_minidump,
                on_message,
            ));
            let stale_timeout = Some(stale_timeout);

            server
                .run(handler, &shutdown, stale_timeout)
                .map_err(Error::RunServer)
        })
}
