//! purple-net: relays packets between `purple-core` and the network, sending real packets
//! only in the slots of a constant-rate cover stream (see [`purple_net::scheduler`]).
//!
//! Usage: `purple-net [--katzenpost <socket> | --dev-provider <addr>]
//! [--send-interval-ms <ms>]`. With `--katzenpost` it stores boxes on Pigeonhole through
//! the kpclientd listening on `socket`, and may not open any other connection. With
//! `--dev-provider` it forwards to a local `purple-devprovider`, so several purple
//! instances on one machine can talk. With neither, it uses an in-memory network only
//! this instance can see. `--send-interval-ms` is the mean gap between packets.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use landlock::RulesetStatus;
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_ipc::{NET_CORE_FD, NetMsg, inherited_stream};
use purple_net::katzenpost::PigeonholeTransport;
use purple_net::scheduler::Scheduler;
use purple_net::{DevProviderTransport, Done, FakeTransport, ReadDone, Sink, Transport};

const NAME: &str = "purple-net";
const USAGE: &str = "usage: purple-net [--katzenpost <socket> | --dev-provider <addr>] \
                     [--send-interval-ms <ms>]";
/// One packet a second on average: about 7 MB an hour of 2 KB packets.
const DEFAULT_SEND_INTERVAL: Duration = Duration::from_secs(1);
/// How long the in-memory network keeps packets nobody fetched (cover traffic).
const FAKE_RETENTION: Duration = Duration::from_hours(1);

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
    Ok(options)
}

#[expect(unsafe_code, reason = "adopting the socket the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    let options = parse_args(std::env::args().skip(1))?;
    // With Katzenpost, kpclientd does all the networking: purple-net only needs its socket.
    let network = match options.store {
        Store::Katzenpost(_) => Network::Local,
        Store::InMemory | Store::DevProvider(_) => Network::Allowed,
    };
    note_sandbox(&restrict(&Policy {
        writable: &[],
        network,
    })?);
    // SAFETY: the launcher hands this fd to purple-net and nothing else here uses it.
    let core = unsafe { inherited_stream(NET_CORE_FD)? };
    let interval = options.send_interval;
    match options.store {
        Store::Katzenpost(socket) => serve(
            core,
            Scheduler::new(PigeonholeTransport::connect(&socket)?, interval),
        ),
        Store::DevProvider(addr) => serve(
            core,
            Scheduler::new(DevProviderTransport::connect(&addr)?, interval),
        ),
        Store::InMemory => serve(
            core,
            Scheduler::new(FakeTransport::with_retention(FAKE_RETENTION), interval),
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
}

/// Queue core's writes into the cover stream and answer its reads, until core closes
/// the socket. Then send what's still queued, at the same rate, and exit.
fn serve(mut core: UnixStream, mut scheduler: Scheduler<impl Transport>) -> io::Result<()> {
    let (events_tx, events) = mpsc::channel();
    spawn_request_reader(core.try_clone()?, events_tx.clone());
    let done_sink = forward_done(events_tx);
    loop {
        let wait = scheduler
            .next_tick()
            .saturating_duration_since(Instant::now());
        match events.recv_timeout(wait) {
            Ok(Event::Core(Ok(NetMsg::Write { at, packet }))) => scheduler.enqueue(at, packet),
            Ok(Event::Core(Ok(NetMsg::Read { at } | NetMsg::ReadCover { at }))) => {
                scheduler.read(&at, &done_sink)?;
            }
            Ok(Event::Core(Ok(
                NetMsg::Found { .. }
                | NetMsg::Empty { .. }
                | NetMsg::Written { .. }
                | NetMsg::Taken { .. }
                | NetMsg::Status(_)
                // Until purple-net can report Blocked, core never sends a choice.
                | NetMsg::Choose(_),
            ))) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "purple-core sent a message only purple-net may send",
                ));
            }
            Ok(Event::Core(Err(err))) => return Err(err),
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
    }
}
