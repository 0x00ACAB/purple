//! Boxes over Tor: one connection, on its own circuit and thread, per stream.
//!
//! A slow circuit only holds up its own stream. Cover writes and padding reads go over a random
//! existing connection, so they never build circuits of their own.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, PoisonError, RwLock};
use std::thread;
use std::time::Duration;

use purple_ipc::{BoxRef, Packet};
use rand::seq::IteratorRandom as _;

use super::socks::{COVER_ISOLATION, isolation_key, socks_connect};
use crate::noise::NoiseStream;
use crate::{ProviderMsg, Sink, Transport, box_address, random_box, report, report_write};

const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_mins(1);
/// Read attempts before a read counts as finding nothing; core asks again next poll.
const READ_ATTEMPTS: u32 = 2;

/// A connection to the store.
pub trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

/// Opens connections to the store.
pub trait Dial: Send + Sync {
    /// A new connection on the circuit for `isolation`.
    ///
    /// # Errors
    /// Fails if the store can't be reached.
    fn dial(&self, isolation: &str) -> io::Result<Box<dyn Conn>>;
}

/// Through tor's SOCKS socket to the store's onion service.
#[derive(Debug)]
pub struct OnionDial {
    /// tor's SOCKS socket.
    pub socks: PathBuf,
    /// The store's onion address.
    pub host: String,
    /// The onion service's port.
    pub port: u16,
}

impl Dial for OnionDial {
    fn dial(&self, isolation: &str) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(socks_connect(
            &self.socks,
            isolation,
            &self.host,
            self.port,
        )?))
    }
}

/// Through purple-relay to the store's direct port, encrypted with Noise to the store's
/// pinned key. No circuits, so the isolation key is unused.
#[derive(Debug)]
pub struct DirectDial {
    /// purple-relay's socket.
    pub relay: PathBuf,
    /// The store's static Noise key.
    pub key: [u8; 32],
}

impl Dial for DirectDial {
    fn dial(&self, _isolation: &str) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(NoiseStream::client(
            UnixStream::connect(&self.relay)?,
            &self.key,
        )?))
    }
}

/// The current way to reach the store, shared with every connection thread. Changing it
/// takes effect at each thread's next connect.
#[derive(Clone)]
pub struct Dialer(Arc<RwLock<Arc<dyn Dial>>>);

impl std::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dialer(..)")
    }
}

impl Dialer {
    /// Start with `dial`.
    #[must_use]
    pub fn new(dial: Arc<dyn Dial>) -> Self {
        Self(Arc::new(RwLock::new(dial)))
    }

    /// Use `dial` from now on.
    pub fn set(&self, dial: Arc<dyn Dial>) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = dial;
    }

    fn current(&self) -> Arc<dyn Dial> {
        Arc::clone(&self.0.read().unwrap_or_else(PoisonError::into_inner))
    }
}

enum Job {
    Write {
        at: BoxRef,
        packet: Packet,
        done: Option<Sink>,
    },
    Read {
        at: BoxRef,
        done: Sink,
    },
}

#[derive(Clone, Copy)]
struct Retry {
    first: Duration,
    max: Duration,
}

/// The Tor (or direct) transport.
#[derive(Debug)]
pub struct TorTransport {
    dialer: Dialer,
    workers: HashMap<String, Sender<Job>>,
    retry_first: Duration,
    retry_max: Duration,
}

impl TorTransport {
    /// Reach the store through `dialer`.
    #[must_use]
    pub fn new(dialer: Dialer) -> Self {
        Self::with_retry(dialer, RETRY_FIRST, RETRY_MAX)
    }

    /// The same, retrying failed writes after `first`, doubling up to `max`.
    #[must_use]
    pub fn with_retry(dialer: Dialer, first: Duration, max: Duration) -> Self {
        Self {
            dialer,
            workers: HashMap::new(),
            retry_first: first,
            retry_max: max,
        }
    }

    fn send(&mut self, key: String, job: Job) -> io::Result<()> {
        let retry = Retry {
            first: self.retry_first,
            max: self.retry_max,
        };
        let dialer = self.dialer.clone();
        let worker = self.workers.entry(key.clone()).or_insert_with(|| {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || work(&key, &dialer, retry, &rx));
            tx
        });
        worker
            .send(job)
            .map_err(|_| io::Error::other("a store connection thread died"))
    }

    /// A random existing connection's key, or the cover circuit's if there are none.
    fn any_key(&self) -> String {
        self.workers
            .keys()
            .choose(&mut rand::rng())
            .cloned()
            .unwrap_or_else(|| COVER_ISOLATION.to_owned())
    }
}

impl Transport for TorTransport {
    fn write(&mut self, at: &BoxRef, packet: Packet, done: Option<&Sink>) -> io::Result<()> {
        let job = Job::Write {
            at: *at,
            packet,
            done: done.cloned(),
        };
        self.send(isolation_key(&at.stream), job)
    }

    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        self.send(
            isolation_key(&at.stream),
            Job::Read {
                at: *at,
                done: done.clone(),
            },
        )
    }

    fn read_cover(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        let key = self.any_key();
        self.send(
            key,
            Job::Read {
                at: *at,
                done: done.clone(),
            },
        )
    }

    fn cover(&mut self) -> io::Result<()> {
        let (at, packet) = random_box()?;
        let key = self.any_key();
        self.send(
            key,
            Job::Write {
                at,
                packet,
                done: None,
            },
        )
    }
}

/// One connection's thread: run its jobs in order, reconnecting as needed.
fn work(key: &str, dialer: &Dialer, retry: Retry, jobs: &mpsc::Receiver<Job>) {
    let mut conn = None;
    for job in jobs {
        match job {
            Job::Write { at, packet, done } => {
                let addr = box_address(&at);
                let mut wait = retry.first;
                loop {
                    let put = ProviderMsg::Put {
                        addr,
                        packet: packet.clone(),
                    };
                    match exchange(&mut conn, dialer, key, &put) {
                        Ok(ProviderMsg::Stored { addr: got }) if got == addr => {
                            report_write(done.as_ref(), &at, true);
                            break;
                        }
                        Ok(ProviderMsg::Taken { addr: got }) if got == addr => {
                            report_write(done.as_ref(), &at, false);
                            break;
                        }
                        Ok(_) => {
                            conn = None;
                            eprintln!(
                                "purple-net: the store answered a write wrongly; retrying in {wait:?}"
                            );
                        }
                        Err(err) => {
                            conn = None;
                            eprintln!(
                                "purple-net: a box write failed, retrying in {wait:?}: {err}"
                            );
                        }
                    }
                    thread::sleep(wait);
                    wait = wait.saturating_mul(2).min(retry.max);
                }
            }
            Job::Read { at, done } => {
                let addr = box_address(&at);
                let mut found = None;
                for _ in 0..READ_ATTEMPTS {
                    match exchange(&mut conn, dialer, key, &ProviderMsg::Get { addr }) {
                        Ok(ProviderMsg::Found { addr: got, packet }) if got == addr => {
                            found = Some(packet);
                            break;
                        }
                        Ok(ProviderMsg::Empty { addr: got }) if got == addr => break,
                        Ok(_) | Err(_) => conn = None,
                    }
                }
                report(&done, &at, Ok(found));
            }
        }
    }
}

/// Send `msg` and wait for the answer, connecting first if needed.
fn exchange(
    conn: &mut Option<Box<dyn Conn>>,
    dialer: &Dialer,
    key: &str,
    msg: &ProviderMsg,
) -> io::Result<ProviderMsg> {
    let c = match conn {
        Some(c) => c,
        None => conn.insert(dialer.current().dial(key)?),
    };
    msg.write_to(c)?;
    c.flush()?;
    ProviderMsg::read_from(c)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the store hung up"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;

    use purple_ipc::{PACKET_LEN, Packet, SEED_LEN, StreamSeed};

    use super::*;
    use crate::{BoxStore, Done, ReadDone, serve_provider};

    /// A store reached over socket pairs, with faults on demand.
    #[derive(Default)]
    struct MemDial {
        store: BoxStore,
        refuse: AtomicBool,
        /// Store the next put, then hang up without answering.
        drop_after_put: AtomicBool,
        slow: Mutex<Option<String>>,
        dialed: Mutex<Vec<String>>,
        dials: AtomicUsize,
    }

    impl Dial for MemDial {
        fn dial(&self, isolation: &str) -> io::Result<Box<dyn Conn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.dialed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(isolation.to_owned());
            if self.refuse.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "store down",
                ));
            }
            if self
                .slow
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_deref()
                == Some(isolation)
            {
                thread::sleep(Duration::from_secs(2));
            }
            let (ours, mut theirs) = UnixStream::pair()?;
            let store = self.store.clone();
            if self.drop_after_put.swap(false, Ordering::SeqCst) {
                thread::spawn(move || {
                    if let Ok(Some(ProviderMsg::Put { addr, packet })) =
                        ProviderMsg::read_from(&mut theirs)
                    {
                        store.put(addr, packet).unwrap();
                    }
                });
            } else {
                thread::spawn(move || serve_provider(&mut theirs, &store, None).ok());
            }
            Ok(Box::new(ours))
        }
    }

    fn net(dial: &Arc<MemDial>) -> TorTransport {
        let d: Arc<dyn Dial> = dial.clone();
        TorTransport::with_retry(
            Dialer::new(d),
            Duration::from_millis(20),
            Duration::from_millis(100),
        )
    }

    fn at(seed: u8, index: u64) -> BoxRef {
        BoxRef {
            stream: StreamSeed([seed; SEED_LEN]),
            index,
        }
    }

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    fn next(rx: &mpsc::Receiver<Done>) -> Done {
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn writes_and_reads_round_trip_on_a_circuit_per_stream() {
        let dial = Arc::new(MemDial::default());
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        assert!(matches!(next(&rx), Done::Written(got) if got == at(1, 0)));
        t.write(&at(2, 0), packet(2), Some(&tx)).unwrap();
        assert!(matches!(next(&rx), Done::Written(_)));
        t.read(&at(1, 0), &tx).unwrap();
        assert!(
            matches!(next(&rx), Done::Read(ReadDone { packet: Ok(Some(p)), .. }) if p == packet(1))
        );
        let dialed = dial.dialed.lock().unwrap().clone();
        assert_eq!(
            dialed,
            [
                isolation_key(&at(1, 0).stream),
                isolation_key(&at(2, 0).stream)
            ]
        );
    }

    #[test]
    fn cover_traffic_rides_existing_circuits() {
        let dial = Arc::new(MemDial::default());
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        next(&rx);
        for _ in 0..10 {
            t.cover().unwrap();
            t.read_cover(&at(9, 9), &tx).unwrap();
            next(&rx);
        }
        assert_eq!(
            dial.dials.load(Ordering::SeqCst),
            1,
            "no new circuit for cover traffic"
        );
    }

    #[test]
    fn cover_traffic_with_no_streams_uses_the_cover_circuit() {
        let dial = Arc::new(MemDial::default());
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.read_cover(&at(9, 9), &tx).unwrap();
        next(&rx);
        assert_eq!(dial.dialed.lock().unwrap().as_slice(), [COVER_ISOLATION]);
    }

    #[test]
    fn unreachable_store_retries_without_reporting() {
        let dial = Arc::new(MemDial::default());
        dial.refuse.store(true, Ordering::SeqCst);
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        assert!(
            rx.recv_timeout(Duration::from_millis(400)).is_err(),
            "nothing reported while down"
        );
        assert!(dial.dials.load(Ordering::SeqCst) >= 3, "kept retrying");
        dial.refuse.store(false, Ordering::SeqCst);
        assert!(
            matches!(next(&rx), Done::Written(_)),
            "lands once the store is back"
        );
    }

    #[test]
    fn reads_of_an_unreachable_store_come_back_empty() {
        let dial = Arc::new(MemDial::default());
        dial.refuse.store(true, Ordering::SeqCst);
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.read(&at(1, 0), &tx).unwrap();
        assert!(matches!(
            next(&rx),
            Done::Read(ReadDone {
                packet: Ok(None),
                ..
            })
        ));
    }

    #[test]
    fn dropped_connection_mid_write_is_retried() {
        let dial = Arc::new(MemDial::default());
        dial.drop_after_put.store(true, Ordering::SeqCst);
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        // The first put landed but its answer was lost; the retry finds the box taken, and
        // core reads it back to see that it's its own.
        assert!(matches!(next(&rx), Done::Taken(got) if got == at(1, 0)));
        assert_eq!(
            dial.store.get(&box_address(&at(1, 0))).unwrap(),
            Some(packet(1))
        );
    }

    #[test]
    fn slow_circuit_does_not_block_other_streams() {
        let dial = Arc::new(MemDial::default());
        *dial.slow.lock().unwrap() = Some(isolation_key(&at(1, 0).stream));
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        t.write(&at(2, 0), packet(2), Some(&tx)).unwrap();
        let first = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(first, Done::Written(got) if got == at(2, 0)));
    }

    #[test]
    fn switching_the_dialer_moves_new_connections() {
        let down = Arc::new(MemDial::default());
        down.refuse.store(true, Ordering::SeqCst);
        let up = Arc::new(MemDial::default());
        let d: Arc<dyn Dial> = down;
        let dialer = Dialer::new(d);
        let mut t = TorTransport::with_retry(
            dialer.clone(),
            Duration::from_millis(20),
            Duration::from_millis(50),
        );
        let (tx, rx) = mpsc::channel();
        t.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        thread::sleep(Duration::from_millis(100));
        let u: Arc<dyn Dial> = up.clone();
        dialer.set(u);
        assert!(matches!(next(&rx), Done::Written(_)));
        assert!(up.store.get(&box_address(&at(1, 0))).unwrap().is_some());
    }
}
