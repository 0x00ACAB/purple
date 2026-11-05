//! purple-net: relays packets between `purple-core` and the network, sending real packets
//! only in the slots of a constant-rate cover stream (see [`purple_net::scheduler`]).
//!
//! Usage: `purple-net [--katzenpost <socket> | --dev-provider <addr> | --tor <socks>
//! --tor-control <socket> --tor-cookie <file> --onion <host>:<port> [--direct-relay
//! <socket> --direct-key <hex>]] [--send-interval-ms <ms>]`. With `--tor` it reaches the
//! store's onion service through tor's sockets, and falls back to bridges and then, if the
//! user says so, to the store's direct port through purple-relay; it opens no network
//! connection of its own. With `--katzenpost` it stores boxes on Pigeonhole through
//! the kpclientd listening on `socket`, and may not open any other connection. With
//! `--dev-provider` it forwards to a local `purple-devprovider`, so several purple
//! instances on one machine can talk. With neither, it uses an in-memory network only
//! this instance can see. `--send-interval-ms` is the mean gap between packets.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use landlock::RulesetStatus;
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_ipc::{NET_CORE_FD, NetChoice, NetMsg, NetStatus, inherited_stream};
use purple_net::katzenpost::PigeonholeTransport;
use purple_net::scheduler::Scheduler;
use purple_net::tor::driver::{TorSetup, drive};
use purple_net::tor::fallback::STALL;
use purple_net::tor::transport::{Dialer, TorTransport};
use purple_net::{DevProviderTransport, Done, FakeTransport, ReadDone, Sink, Transport};

const NAME: &str = "purple-net";
const USAGE: &str = "usage: purple-net [--katzenpost <socket> | --dev-provider <addr> | \
                     --tor <socks> --tor-control <socket> --tor-cookie <file> \
                     --onion <host>:<port> [--direct-relay <socket> --direct-key <hex>]] \
                     [--send-interval-ms <ms>]";
/// One packet a second on average: about 7 MB an hour of 2 KB packets.
const DEFAULT_SEND_INTERVAL: Duration = Duration::from_secs(1);
/// How long the in-memory network keeps packets nobody fetched (cover traffic).
const FAKE_RETENTION: Duration = Duration::from_hours(1);
/// How often the Tor driver checks tor's bootstrap progress.
const DRIVE_EVERY: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{NAME}: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Where boxes are stored.
#[derive(Debug, PartialEq, Eq)]
enum Store {
    InMemory,
    DevProvider(String),
    Katzenpost(PathBuf),
    Tor(TorSetup),
}

/// The Tor flags as given, before they're checked as a set.
#[derive(Default)]
struct TorFlags {
    socks: Option<PathBuf>,
    control: Option<PathBuf>,
    cookie: Option<PathBuf>,
    onion: Option<String>,
    relay: Option<PathBuf>,
    key: Option<String>,
}

impl TorFlags {
    const fn is_empty(&self) -> bool {
        self.socks.is_none()
            && self.control.is_none()
            && self.cookie.is_none()
            && self.onion.is_none()
            && self.relay.is_none()
            && self.key.is_none()
    }

    /// All four Tor flags, an onion address, and either both direct flags or neither.
    fn into_setup(self) -> io::Result<TorSetup> {
        let usage = || io::Error::other(USAGE);
        let (Some(socks), Some(control), Some(cookie), Some(onion)) =
            (self.socks, self.control, self.cookie, self.onion)
        else {
            return Err(usage());
        };
        let (host, port) = parse_onion(&onion)?;
        let direct = match (self.relay, self.key) {
            (Some(relay), Some(key)) => Some((relay, parse_key(&key)?)),
            (None, None) => None,
            _ => return Err(usage()),
        };
        Ok(TorSetup {
            socks,
            control,
            cookie,
            host,
            port,
            direct,
            // Before restrict, while the plugin binaries can still be looked for.
            bridges: purple_net::tor::bridges::available(),
            stall: STALL,
        })
    }
}

/// `<56 base32 chars>.onion:<port>`.
fn parse_onion(text: &str) -> io::Result<(String, u16)> {
    let bad = || io::Error::other("--onion takes a v3 onion address and port");
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    let name = host.strip_suffix(".onion").ok_or_else(bad)?;
    if name.len() != 56
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return Err(bad());
    }
    let port = port.parse().map_err(|_| bad())?;
    Ok((host.to_owned(), port))
}

/// 64 hex characters.
fn parse_key(text: &str) -> io::Result<[u8; 32]> {
    let bad = || io::Error::other("--direct-key takes 64 hex characters");
    if text.len() != 64 {
        return Err(bad());
    }
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| bad())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(key)
}

struct Options {
    store: Store,
    send_interval: Duration,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let mut options = Options {
        store: Store::InMemory,
        send_interval: DEFAULT_SEND_INTERVAL,
    };
    let mut tor = TorFlags::default();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| io::Error::other(USAGE));
        let mut set_store = |store| {
            if options.store != Store::InMemory {
                return Err(io::Error::other(USAGE));
            }
            options.store = store;
            Ok(())
        };
        match arg.as_str() {
            "--dev-provider" => set_store(Store::DevProvider(value()?))?,
            "--katzenpost" => set_store(Store::Katzenpost(value()?.into()))?,
            "--tor" => tor.socks = Some(value()?.into()),
            "--tor-control" => tor.control = Some(value()?.into()),
            "--tor-cookie" => tor.cookie = Some(value()?.into()),
            "--onion" => tor.onion = Some(value()?),
            "--direct-relay" => tor.relay = Some(value()?.into()),
            "--direct-key" => tor.key = Some(value()?),
            "--send-interval-ms" => {
                let ms: u64 = value()?.parse().map_err(|_| io::Error::other(USAGE))?;
                if ms == 0 {
                    return Err(io::Error::other("--send-interval-ms must be at least 1"));
                }
                options.send_interval = Duration::from_millis(ms);
            }
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    if !tor.is_empty() {
        if options.store != Store::InMemory {
            return Err(io::Error::other(USAGE));
        }
        options.store = Store::Tor(tor.into_setup()?);
    }
    Ok(options)
}

#[expect(unsafe_code, reason = "adopting the socket the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    let options = parse_args(std::env::args().skip(1))?;
    // With Katzenpost or Tor, kpclientd or tor (and purple-relay) do all the networking:
    // purple-net only needs their sockets.
    let network = match options.store {
        Store::Katzenpost(_) | Store::Tor(_) => Network::Local,
        Store::InMemory | Store::DevProvider(_) => Network::Allowed,
    };
    let readable = readable_dirs(&options.store);
    let readable: Vec<&Path> = readable.iter().map(PathBuf::as_path).collect();
    note_sandbox(&restrict(&Policy {
        writable: &readable,
        network,
    })?);
    // SAFETY: the launcher hands this fd to purple-net and nothing else here uses it.
    let core = unsafe { inherited_stream(NET_CORE_FD)? };
    let interval = options.send_interval;
    match options.store {
        Store::Tor(setup) => {
            let dialer = Dialer::new(Arc::new(setup.onion()));
            let (status_tx, status_rx) = mpsc::channel();
            let (choice_tx, choice_rx) = mpsc::channel();
            let driver_dialer = dialer.clone();
            thread::spawn(move || {
                drive(&setup, &driver_dialer, &status_tx, &choice_rx, DRIVE_EVERY);
            });
            serve(
                core,
                Scheduler::new(TorTransport::new(dialer), interval),
                Some((status_rx, choice_tx)),
            )
        }
        Store::Katzenpost(socket) => serve(
            core,
            Scheduler::new(PigeonholeTransport::connect(&socket)?, interval),
            None,
        ),
        Store::DevProvider(addr) => serve(
            core,
            Scheduler::new(DevProviderTransport::connect(&addr)?, interval),
            None,
        ),
        Store::InMemory => serve(
            core,
            Scheduler::new(FakeTransport::with_retention(FAKE_RETENTION), interval),
            None,
        ),
    }
}

/// What the main loop waits for.
enum Event {
    /// A request from core, or the error that ended core's socket.
    Core(io::Result<NetMsg>),
    /// Core closed its socket.
    CoreClosed,
    /// A read or write finished.
    Done(Done),
    /// The Tor driver's latest status.
    Status(NetStatus),
}

/// Queue core's writes into the cover stream and answer its reads, until core closes
/// the socket. Then send what's still queued, at the same rate, and exit. With `tor`, the
/// driver's status goes to core and core's choices go to the driver.
fn serve(
    mut core: UnixStream,
    mut scheduler: Scheduler<impl Transport>,
    tor: Option<(Receiver<NetStatus>, Sender<NetChoice>)>,
) -> io::Result<()> {
    let (events_tx, events) = mpsc::channel();
    spawn_request_reader(core.try_clone()?, events_tx.clone());
    let choices = tor.map(|(status, choices)| {
        forward_status(status, events_tx.clone());
        choices
    });
    let done_sink = forward_done(events_tx);
    loop {
        let wait = scheduler
            .next_tick()
            .saturating_duration_since(Instant::now());
        match events.recv_timeout(wait) {
            Ok(Event::Core(Ok(NetMsg::Write { at, packet }))) => scheduler.enqueue(at, packet),
            Ok(Event::Core(Ok(NetMsg::Read { at }))) => scheduler.read(&at, &done_sink)?,
            Ok(Event::Core(Ok(NetMsg::ReadCover { at }))) => {
                scheduler.read_cover(&at, &done_sink)?;
            }
            Ok(Event::Core(Ok(NetMsg::Choose(choice)))) => match &choices {
                Some(choices) => {
                    choices.send(choice).ok();
                }
                None => eprintln!("{NAME}: no fallback to choose for"),
            },
            Ok(Event::Core(Ok(NetMsg::UseDirect))) => eprintln!("{NAME}: no direct route yet"),
            Ok(Event::Core(Ok(
                NetMsg::Found { .. }
                | NetMsg::Empty { .. }
                | NetMsg::Written { .. }
                | NetMsg::Taken { .. }
                | NetMsg::Status(_),
            ))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "purple-core sent a message only purple-net may send",
                ));
            }
            Ok(Event::Core(Err(err))) => return Err(err),
            Ok(Event::Status(status)) => match NetMsg::Status(status).write_to(&mut core) {
                Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                    return drain(&mut scheduler, &done_sink);
                }
                other => other?,
            },
            Ok(Event::Done(done)) => {
                let reply = match done {
                    Done::Read(ReadDone { at, packet }) => {
                        packet?.map_or(NetMsg::Empty { at }, |packet| NetMsg::Found { at, packet })
                    }
                    Done::Written(at) => NetMsg::Written { at },
                    Done::Taken(at) => NetMsg::Taken { at },
                };
                match reply.write_to(&mut core) {
                    // Core closed its socket and the reader hasn't noticed yet.
                    Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                        return drain(&mut scheduler, &done_sink);
                    }
                    other => other?,
                }
            }
            Ok(Event::CoreClosed) => return drain(&mut scheduler, &done_sink),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("purple-net's event channel closed"));
            }
        }
        if Instant::now() >= scheduler.next_tick() {
            scheduler.tick(&done_sink)?;
        }
    }
}

/// Send the packets still queued when core exits, without breaking the rate, and let
/// the transport finish writes in flight. Core is gone, so nobody hears they landed; it
/// sends anything it wasn't told about again next time.
fn drain(scheduler: &mut Scheduler<impl Transport>, done: &Sink) -> io::Result<()> {
    while scheduler.queued() > 0 {
        thread::sleep(
            scheduler
                .next_tick()
                .saturating_duration_since(Instant::now()),
        );
        scheduler.tick(done)?;
    }
    scheduler.finish()
}

/// A sink for finished reads and writes that feeds them into the main loop's events.
fn forward_done(events: Sender<Event>) -> Sink {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for done in rx {
            if events.send(Event::Done(done)).is_err() {
                return;
            }
        }
    });
    tx
}

/// Directories purple-net must read after [`restrict`]: tor's socket directory, for the
/// control cookie. Landlock grants them as writable, but bwrap mounts them read-only.
fn readable_dirs(store: &Store) -> Vec<PathBuf> {
    match store {
        Store::Tor(setup) => setup
            .cookie
            .parent()
            .map(Path::to_path_buf)
            .into_iter()
            .collect(),
        Store::InMemory | Store::DevProvider(_) | Store::Katzenpost(_) => Vec::new(),
    }
}

/// Feed the Tor driver's status reports into the main loop's events.
fn forward_status(reports: Receiver<NetStatus>, events: Sender<Event>) {
    thread::spawn(move || {
        for status in reports {
            if events.send(Event::Status(status)).is_err() {
                return;
            }
        }
    });
}

/// Read requests from core on their own thread so the main loop can tick on time.
fn spawn_request_reader(mut core: UnixStream, events: Sender<Event>) {
    thread::spawn(move || {
        loop {
            let event = match NetMsg::read_from(&mut core) {
                Ok(Some(msg)) => Event::Core(Ok(msg)),
                Ok(None) => Event::CoreClosed,
                Err(err) => Event::Core(Err(err)),
            };
            let last = !matches!(event, Event::Core(Ok(_)));
            // If the main loop is gone, so is the reason to read.
            if events.send(event).is_err() || last {
                return;
            }
        }
    });
}

/// Log how much of the sandbox the kernel enforced, if not all of it.
fn note_sandbox(report: &Report) {
    if report.landlock != RulesetStatus::FullyEnforced {
        eprintln!(
            "{NAME}: warning: Landlock only {:?} on this kernel",
            report.landlock
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> io::Result<Options> {
        parse_args(args.iter().map(|&a| a.to_owned()))
    }

    #[test]
    fn tor_mode_may_read_tors_socket_dir_for_the_cookie() {
        let tor = parse(&[
            "--tor",
            "/run/tor/socks.sock",
            "--tor-control",
            "/run/tor/control.sock",
            "--tor-cookie",
            "/run/tor/control.cookie",
            "--onion",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion:80",
        ])
        .unwrap();
        assert_eq!(readable_dirs(&tor.store), [PathBuf::from("/run/tor")]);
        assert!(readable_dirs(&Store::InMemory).is_empty());
    }

    #[test]
    fn parses_options() {
        let defaults = parse(&[]).unwrap();
        assert_eq!(defaults.send_interval, DEFAULT_SEND_INTERVAL);
        assert_eq!(defaults.store, Store::InMemory);
        let set = parse(&["--send-interval-ms", "50", "--dev-provider", "127.0.0.1:1"]).unwrap();
        assert_eq!(set.send_interval, Duration::from_millis(50));
        assert_eq!(set.store, Store::DevProvider("127.0.0.1:1".into()));
        let kp = parse(&["--katzenpost", "/run/kp/kpclientd.sock"]).unwrap();
        assert_eq!(kp.store, Store::Katzenpost("/run/kp/kpclientd.sock".into()));
        assert!(parse(&["--katzenpost", "/s", "--dev-provider", "127.0.0.1:1"]).is_err());
        assert!(parse(&["--send-interval-ms", "0"]).is_err());
        assert!(parse(&["--send-interval-ms", "x"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
        let key = "ab".repeat(32);
        let tor = parse(&[
            "--tor",
            "/run/tor/socks.sock",
            "--tor-control",
            "/run/tor/control.sock",
            "--tor-cookie",
            "/run/tor/control.cookie",
            "--onion",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion:80",
            "--direct-relay",
            "/run/relay/relay.sock",
            "--direct-key",
            &key,
        ])
        .unwrap();
        let Store::Tor(setup) = tor.store else {
            panic!("expected Tor")
        };
        assert_eq!(setup.port, 80);
        assert_eq!(setup.direct.as_ref().map(|(_, k)| *k), Some([0xab; 32]));
        assert!(
            parse(&["--tor", "/s", "--onion", "store.example.com:80"]).is_err(),
            "onion only"
        );
        assert!(
            parse(&["--onion", "x.onion:80"]).is_err(),
            "--onion needs --tor"
        );
        assert!(
            parse(&[
                "--tor",
                "/s",
                "--tor-control",
                "/c",
                "--tor-cookie",
                "/k",
                "--onion",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion:80",
                "--direct-key",
                &key
            ])
            .is_err(),
            "a key without a relay"
        );
    }
}
