//! The Pigeonhole transport: boxes stored by Katzenpost's replicas, reached through
//! couriers over the mixnet, by way of a local kpclientd.
//!
//! Every purple box is its own one-box BACAP stream. Its seed is derived from the purple
//! stream seed and the index (see [`box_seed`]), and the daemon turns that into the
//! capabilities and box ID. So reaching any box costs the same, padding reads of random
//! boxes included, and purple-net keeps no per-stream state. Replicas see unrelated box
//! IDs; couriers don't learn who sent a request, since it came through the mixnet.
//!
//! Cover traffic is the daemon's job here: it sends one Sphinx packet per Poisson tick,
//! a decoy when nothing is queued, so [`Transport::cover`] does nothing. Writing random
//! boxes as well would only fill the replicas with junk.

mod cbor;
mod client;

use std::io;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use purple_ipc::{BoxRef, PACKET_LEN, Packet};
use sha2::Sha256;

pub use client::{Client, Envelope, Fetched, Keypair};

use crate::{Done, ReadDone, Sink, Transport};

/// Reads in flight at once. `purple-core` sends at most 256 per poll.
const READ_WORKERS: usize = 32;
/// Writes in flight at once. The scheduler sends about one a second.
const WRITE_WORKERS: usize = 8;
/// How long a read may take before it counts as finding nothing. `purple-core` polls the
/// box again later.
const READ_TIMEOUT: Duration = Duration::from_mins(2);
/// How long to wait for writes still in flight at exit.
const FINISH_TIMEOUT: Duration = Duration::from_mins(1);
/// The wait before retrying a failed write; it doubles with each failure up to
/// [`WRITE_RETRY_MAX`].
const WRITE_RETRY_FIRST: Duration = Duration::from_secs(5);
const WRITE_RETRY_MAX: Duration = Duration::from_mins(2);

/// Namenlos's `MaxPlaintextPayloadLength`. The daemon's geometry is checked at runtime;
/// this catches a `PACKET_LEN` change that would break the network purple targets.
const NAMENLOS_MAX_PAYLOAD: usize = 1549;
const _: () = assert!(PACKET_LEN <= NAMENLOS_MAX_PAYLOAD);

type Job = Box<dyn FnOnce() + Send>;

/// Boxes on Pigeonhole, through kpclientd.
#[derive(Debug)]
pub struct PigeonholeTransport {
    client: Arc<Client>,
    reads: Sender<Job>,
    writes: Option<Sender<Job>>,
    /// Disconnects once every write worker has exited.
    writers_gone: Receiver<()>,
}

impl PigeonholeTransport {
    /// Connect to kpclientd at `socket`.
    ///
    /// # Errors
    /// Fails if the daemon can't be reached, or its boxes are too small for purple.
    pub fn connect(socket: &Path) -> io::Result<Self> {
        Self::over(Client::connect(socket)?)
    }

    fn over(client: Client) -> io::Result<Self> {
        if client.max_payload() < PACKET_LEN {
            return Err(io::Error::other(format!(
                "kpclientd's boxes hold {} bytes; purple needs {PACKET_LEN}",
                client.max_payload()
            )));
        }
        let (reads, read_jobs) = mpsc::channel();
        let (writes, write_jobs) = mpsc::channel();
        let (writers_alive, writers_gone) = mpsc::channel();
        spawn_workers(READ_WORKERS, read_jobs, None);
        spawn_workers(WRITE_WORKERS, write_jobs, Some(&writers_alive));
        Ok(Self {
            client: Arc::new(client),
            reads,
            writes: Some(writes),
            writers_gone,
        })
    }
}

impl Transport for PigeonholeTransport {
    fn write(&mut self, at: &BoxRef, packet: Packet, done: Option<&Sink>) -> io::Result<()> {
        let client = Arc::clone(&self.client);
        let seed = box_seed(at);
        let at = *at;
        let done = done.cloned();
        let job: Job = Box::new(move || {
            match with_retries(
                || write_box(&client, &seed, &packet),
                WRITE_RETRY_FIRST,
                WRITE_RETRY_MAX,
            ) {
                Ok(()) => {
                    if let Some(done) = done {
                        done.send(Done::Written(at)).ok();
                    }
                }
                Err(err) => eprintln!("purple-net: lost a box write: {err}"),
            }
        });
        self.writes
            .as_ref()
            .ok_or_else(stopped)?
            .send(job)
            .map_err(|_| stopped())
    }

    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        let client = Arc::clone(&self.client);
        let at = *at;
        let done = done.clone();
        let job: Job = Box::new(move || {
            let packet = read_box(&client, &box_seed(&at));
            done.send(Done::Read(ReadDone { at, packet })).ok();
        });
        self.reads.send(job).map_err(|_| stopped())
    }

    fn cover(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        // Workers finish what's queued, then exit once the channel closes.
        self.writes = None;
        let deadline = Instant::now()
            .checked_add(FINISH_TIMEOUT)
            .unwrap_or_else(Instant::now);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.writers_gone.recv_timeout(left) {
                Ok(()) => {}
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "gave up waiting for box writes to finish",
                    ));
                }
            }
        }
    }
}

/// The BACAP seed for box `at`: HKDF keyed by the stream seed, over the index. Without the
/// stream seed, one box's seed says nothing about another's.
#[must_use]
pub fn box_seed(at: &BoxRef) -> [u8; 32] {
    let mut seed = [0u8; 32];
    // A 32-byte output is always within HKDF-SHA256's limit, so this can't fail.
    Hkdf::<Sha256>::new(Some(b"purple pigeonhole box v1"), &at.stream.0)
        .expand(&at.index.to_be_bytes(), &mut seed)
        .ok();
    seed
}

fn write_box(client: &Client, seed: &[u8; 32], packet: &Packet) -> io::Result<()> {
    let keys = client.new_keypair(seed)?;
    let envelope = client.encrypt_write(packet.as_bytes(), &keys.write_cap, &keys.first_index)?;
    client.send_write(&envelope, &keys.write_cap)
}

/// Run `attempt` until it succeeds, waiting `first` after the first failure and twice as
/// long after each one after that, up to `max`. Only a lost daemon connection
/// (`BrokenPipe`) ends it early: anything else may be the network, and a write that
/// actually landed the first time succeeds when repeated.
fn with_retries(
    mut attempt: impl FnMut() -> io::Result<()>,
    first: Duration,
    max: Duration,
) -> io::Result<()> {
    let mut wait = first;
    loop {
        match attempt() {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => return Err(err),
            Err(err) => {
                eprintln!("purple-net: a box write failed, retrying in {wait:?}: {err}");
                thread::sleep(wait);
                wait = wait.saturating_mul(2).min(max);
            }
        }
    }
}

/// Read one box. Only a lost daemon connection is an error: anything else (a timeout, a
/// courier refusing, a box of the wrong size) reads as nothing, and core tries again on a
/// later poll.
fn read_box(client: &Client, seed: &[u8; 32]) -> io::Result<Option<Packet>> {
    let fetched = client.new_keypair(seed).and_then(|keys| {
        let envelope = client.encrypt_read(&keys.read_cap, &keys.first_index)?;
        client.send_read(&envelope, &keys.read_cap, &keys.first_index, READ_TIMEOUT)
    });
    match fetched {
        Ok(Fetched::Box(bytes)) => Ok(Packet::from_slice(&bytes).ok()),
        Ok(Fetched::Nothing) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Err(err),
        Err(err) => {
            if err.kind() != io::ErrorKind::TimedOut {
                eprintln!("purple-net: a box read failed: {err}");
            }
            Ok(None)
        }
    }
}

/// Run jobs from `jobs` on `count` threads. Each holds a clone of `alive` (if any) until
/// it exits, so the receiving end sees a disconnect once all have.
fn spawn_workers(count: usize, jobs: Receiver<Job>, alive: Option<&Sender<()>>) {
    let jobs = Arc::new(Mutex::new(jobs));
    for _ in 0..count {
        let jobs = Arc::clone(&jobs);
        let alive = alive.cloned();
        thread::spawn(move || {
            let _alive = alive;
            loop {
                // Hold the lock only to take a job, not while running it.
                let job = match jobs.lock() {
                    Ok(jobs) => jobs.recv(),
                    Err(_) => return,
                };
                match job {
                    Ok(job) => job(),
                    Err(_) => return,
                }
            }
        });
    }
}

fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "the Pigeonhole transport has stopped",
    )
}

#[cfg(test)]
mod tests {
    use purple_ipc::{SEED_LEN, StreamSeed};
    use sha2::Digest;

    use super::*;

    fn at(seed: u8, index: u64) -> BoxRef {
        BoxRef {
            stream: StreamSeed([seed; SEED_LEN]),
            index,
        }
    }

    #[test]
    fn writes_are_retried_until_they_succeed() {
        let mut failures = 3;
        let mut calls = 0;
        let started = Instant::now();
        with_retries(
            || {
                calls += 1;
                if failures == 0 {
                    return Ok(());
                }
                failures -= 1;
                Err(io::Error::other("no PKI document available"))
            },
            Duration::from_millis(1),
            Duration::from_millis(2),
        )
        .unwrap();
        assert_eq!(calls, 4);
        // Waits of 1, 2 and 2 ms: the backoff stops at the cap.
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn writes_stop_when_the_daemon_is_gone() {
        let mut calls = 0;
        let err = with_retries(
            || {
                calls += 1;
                Err(stopped())
            },
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(calls, 1);
    }

    #[test]
    fn box_seeds_are_unlinkable_and_stable() {
        let a0 = box_seed(&at(1, 0));
        assert_eq!(a0, box_seed(&at(1, 0)));
        assert_ne!(a0, box_seed(&at(1, 1)));
        assert_ne!(a0, box_seed(&at(2, 0)));
        // Different from the dev provider's address for the same box.
        assert_ne!(a0, crate::box_address(&at(1, 0)).0);
    }

    /// Against a real kpclientd; offline is enough, since keypairs are made locally.
    /// (Encrypting a read or write needs a PKI document, so it fails offline.) Run with
    /// `PURPLE_KPCLIENTD_SOCKET=<path> cargo test -- --ignored`.
    #[test]
    #[ignore = "needs a running kpclientd"]
    fn real_daemon_derives_keypairs_from_the_seed_alone() {
        let socket = std::env::var("PURPLE_KPCLIENTD_SOCKET").unwrap();
        let first = Client::connect(Path::new(&socket)).unwrap();
        let second = Client::connect(Path::new(&socket)).unwrap();
        assert!(first.max_payload() >= PACKET_LEN, "{}", first.max_payload());

        let seed = box_seed(&at(7, 3));
        let a = first.new_keypair(&seed).unwrap();
        let b = second.new_keypair(&seed).unwrap();
        assert_eq!(a.write_cap, b.write_cap);
        assert_eq!(a.read_cap, b.read_cap);
        assert_eq!(a.first_index, b.first_index);
        let other = first.new_keypair(&box_seed(&at(7, 4))).unwrap();
        assert_ne!(a.read_cap, other.read_cap);
        assert_ne!(a.first_index, other.first_index);

        // Printed so runs against separate daemon instances can be compared.
        let digest = Sha256::digest([a.write_cap, a.read_cap, a.first_index].concat());
        println!("keypair digest: {digest:x}");
    }

    /// Against a kpclientd on a live network: write a fresh box, then read it back over a
    /// second connection. Run with `PURPLE_KPCLIENTD_SOCKET=<path> cargo test -- --ignored`;
    /// set `PURPLE_KPCLIENTD_READ_SOCKET` to read through a second daemon instead.
    #[test]
    #[ignore = "needs a kpclientd on a live network"]
    fn real_network_round_trips_a_box() {
        let socket = std::env::var("PURPLE_KPCLIENTD_SOCKET").unwrap();
        let read_socket =
            std::env::var("PURPLE_KPCLIENTD_READ_SOCKET").unwrap_or_else(|_| socket.clone());
        let writer = Client::connect(Path::new(&socket)).unwrap();
        let reader = Client::connect(Path::new(&read_socket)).unwrap();

        let (at, packet) = crate::random_box().unwrap();
        let seed = box_seed(&at);

        let started = Instant::now();
        let keys = reader.new_keypair(&seed).unwrap();
        let empty = reader
            .encrypt_read(&keys.read_cap, &keys.first_index)
            .unwrap();
        let before = reader
            .send_read(&empty, &keys.read_cap, &keys.first_index, READ_TIMEOUT)
            .unwrap();
        assert!(matches!(before, Fetched::Nothing), "{before:?}");
        println!("empty read: {:?}", started.elapsed());

        let started_write = Instant::now();
        write_box(&writer, &seed, &packet).unwrap();
        println!("write: {:?}", started_write.elapsed());

        let started_read = Instant::now();
        let got = read_box(&reader, &seed).unwrap();
        println!("read: {:?}", started_read.elapsed());
        assert_eq!(got.as_ref().map(Packet::as_bytes), Some(packet.as_bytes()));
    }
}
