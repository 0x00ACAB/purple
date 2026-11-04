//! purple-net: relays packets between `purple-core` and the network, sending real packets
//! only in the slots of a constant-rate cover stream (see [`purple_net::scheduler`]).
//!
//! Usage: `purple-net [--dev-provider <addr>] [--send-interval-ms <ms>]`. With
//! `--dev-provider` it forwards to a local `purple-devprovider`, so several purple
//! instances on one machine can talk; without it, it uses an in-memory network only this
//! instance can see. `--send-interval-ms` is the mean gap between packets.

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use landlock::RulesetStatus;
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_ipc::{NET_CORE_FD, NetMsg, inherited_stream};
use purple_net::scheduler::Scheduler;
use purple_net::{DevProviderTransport, FakeTransport, Transport};

const NAME: &str = "purple-net";
const USAGE: &str = "usage: purple-net [--dev-provider <addr>] [--send-interval-ms <ms>]";
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

struct Options {
    dev_provider: Option<String>,
    send_interval: Duration,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let mut options = Options {
        dev_provider: None,
        send_interval: DEFAULT_SEND_INTERVAL,
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| io::Error::other(USAGE));
        match arg.as_str() {
            "--dev-provider" => options.dev_provider = Some(value()?),
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
    note_sandbox(&restrict(&Policy {
        writable: &[],
        network: Network::Allowed,
    })?);
    let options = parse_args(std::env::args().skip(1))?;
    // SAFETY: the launcher hands this fd to purple-net and nothing else here uses it.
    let core = unsafe { inherited_stream(NET_CORE_FD)? };
    // The mixnet transport replaces these once the Nym/Katzenpost choice is made.
    match options.dev_provider {
        Some(addr) => serve(
            core,
            Scheduler::new(DevProviderTransport::connect(&addr)?, options.send_interval),
        ),
        None => serve(
            core,
            Scheduler::new(
                FakeTransport::with_retention(FAKE_RETENTION),
                options.send_interval,
            ),
        ),
    }
}

/// Queue core's writes into the cover stream and answer its reads, until core closes
/// the socket. Then send what's still queued, at the same rate, and exit.
fn serve(mut core: UnixStream, mut scheduler: Scheduler<impl Transport>) -> io::Result<()> {
    let requests = spawn_request_reader(core.try_clone()?);
    loop {
        let wait = scheduler
            .next_tick()
            .saturating_duration_since(Instant::now());
        match requests.recv_timeout(wait) {
            Ok(Ok(NetMsg::Write { at, packet })) => scheduler.enqueue(at, packet),
            Ok(Ok(NetMsg::Read { at })) => match scheduler.read(&at)? {
                Some(packet) => NetMsg::Found { at, packet }.write_to(&mut core)?,
                None => NetMsg::Empty { at }.write_to(&mut core)?,
            },
            Ok(Ok(NetMsg::Found { .. } | NetMsg::Empty { .. })) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "purple-core sent a message only purple-net may send",
                ));
            }
            Ok(Err(err)) => return Err(err),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return drain(&mut scheduler),
        }
        if Instant::now() >= scheduler.next_tick() {
            scheduler.tick()?;
        }
    }
}

/// Send the packets still queued when core exits, without breaking the rate.
fn drain(scheduler: &mut Scheduler<impl Transport>) -> io::Result<()> {
    while scheduler.queued() > 0 {
        thread::sleep(
            scheduler
                .next_tick()
                .saturating_duration_since(Instant::now()),
        );
        scheduler.tick()?;
    }
    Ok(())
}

/// Read requests from core on their own thread so the main loop can tick on time. The
/// channel closes when core closes its socket.
fn spawn_request_reader(mut core: UnixStream) -> Receiver<io::Result<NetMsg>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match NetMsg::read_from(&mut core) {
                Ok(Some(msg)) => {
                    if tx.send(Ok(msg)).is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(err) => {
                    // The main loop stops on this error, so a failed send changes nothing.
                    tx.send(Err(err)).ok();
                    return;
                }
            }
        }
    });
    rx
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
        assert!(defaults.dev_provider.is_none());
        let set = parse(&["--send-interval-ms", "50", "--dev-provider", "127.0.0.1:1"]).unwrap();
        assert_eq!(set.send_interval, Duration::from_millis(50));
        assert_eq!(set.dev_provider.as_deref(), Some("127.0.0.1:1"));
        assert!(parse(&["--send-interval-ms", "0"]).is_err());
        assert!(parse(&["--send-interval-ms", "x"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
    }
}
