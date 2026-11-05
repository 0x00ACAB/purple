//! Boxes over Tor: one connection, on its own circuit and thread, per stream.
//!
//! A slow circuit only holds up its own stream. Cover writes and padding reads go over a random
//! existing connection, so they never build circuits of their own.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use purple_ipc::{BoxRef, Packet};
use rand::Rng as _;
use rand::seq::IteratorRandom as _;

use super::socks::{COVER_ISOLATION, isolation_key, socks_connect};
use crate::noise::NoiseStream;
use crate::{ProviderMsg, Sink, Transport, box_address, random_box, report, report_write};

const RETRY_FIRST: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_mins(1);
/// Read attempts before a read counts as finding nothing; core asks again next poll.
const READ_ATTEMPTS: u32 = 2;
/// Most requests sent on one connection before reading their answers. Keeps what's
/// written ahead (about 25 KB of puts) well inside socket buffers.
const MAX_BATCH: usize = 16;
/// Reads spread over this window: purple-core's poll interval.
const READ_JITTER: Duration = Duration::from_secs(2);
/// How long one connection may sit on a connect, read or write. Building a circuit to an
/// onion service can take tens of seconds; minutes means it's gone.
pub const CONN_TIMEOUT: Duration = Duration::from_mins(2);

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
    /// How long a connect, read or write may take before the connection counts as dead.
    pub timeout: Duration,
}

impl Dial for OnionDial {
    fn dial(&self, isolation: &str) -> io::Result<Box<dyn Conn>> {
        let stream = UnixStream::connect(&self.socks)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        Ok(Box::new(socks_connect(
            stream, isolation, &self.host, self.port,
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
        let stream = UnixStream::connect(&self.relay)?;
        stream.set_read_timeout(Some(CONN_TIMEOUT))?;
        stream.set_write_timeout(Some(CONN_TIMEOUT))?;
        Ok(Box::new(NoiseStream::client(stream, &self.key)?))
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
        /// Cover traffic: one attempt, dropped if it fails, so cover can't pile up while
        /// the store is unreachable.
        cover: bool,
    },
    Read {
        at: BoxRef,
        done: Sink,
        /// Attempts so far.
        tries: u32,
    },
}

impl Job {
    fn request(&self) -> ProviderMsg {
        match self {
            Self::Write { at, packet, .. } => ProviderMsg::Put {
                addr: box_address(at),
                packet: packet.clone(),
            },
            Self::Read { at, .. } => ProviderMsg::Get {
                addr: box_address(at),
            },
        }
    }

    /// Report the store's `answer`; false if it doesn't answer this job.
    fn answer(&self, answer: ProviderMsg) -> bool {
        match (self, answer) {
            (Self::Write { at, done, .. }, ProviderMsg::Stored { addr })
                if addr == box_address(at) =>
            {
                report_write(done.as_ref(), at, true);
            }
            (Self::Write { at, done, .. }, ProviderMsg::Taken { addr })
                if addr == box_address(at) =>
            {
                report_write(done.as_ref(), at, false);
            }
            (Self::Read { at, done, .. }, ProviderMsg::Found { addr, packet })
                if addr == box_address(at) =>
            {
                report(done, at, Ok(Some(packet)));
            }
            (Self::Read { at, done, .. }, ProviderMsg::Empty { addr })
                if addr == box_address(at) =>
            {
                report(done, at, Ok(None));
            }
            _ => return false,
        }
        true
    }

    /// What's left of a job that got no answer: real writes are tried again until they
    /// land, reads up to [`READ_ATTEMPTS`] times and then count as finding nothing (core
    /// asks again next poll), cover writes are dropped.
    fn failed(self) -> Option<Self> {
        match self {
            Self::Write { cover: true, .. } => None,
            write @ Self::Write { .. } => Some(write),
            Self::Read { at, done, tries } => {
                let tries = tries.saturating_add(1);
                if tries >= READ_ATTEMPTS {
                    report(&done, &at, Ok(None));
                    None
                } else {
                    Some(Self::Read { at, done, tries })
                }
            }
        }
    }
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
    /// Each read waits a random time below this before it goes to its connection.
    read_jitter: Duration,
    /// The timer thread holding delayed reads, started with the first one.
    timer: Option<Sender<Delayed>>,
}

impl TorTransport {
    /// Reach the store through `dialer`.
    #[must_use]
    pub fn new(dialer: Dialer) -> Self {
        Self::with_retry(dialer, RETRY_FIRST, RETRY_MAX).with_read_jitter(READ_JITTER)
    }

    /// The same, retrying failed writes after `first`, doubling up to `max`.
    #[must_use]
    pub fn with_retry(dialer: Dialer, first: Duration, max: Duration) -> Self {
        Self {
            dialer,
            workers: HashMap::new(),
            retry_first: first,
            retry_max: max,
            read_jitter: Duration::ZERO,
            timer: None,
        }
    }

    /// Delay each read by its own random time in `[0, window)`, so a client's reads (which
    /// core asks for together, every poll) reach the store on their circuits at unrelated
    /// times and can't be grouped as one person's by when they arrive.
    #[must_use]
    pub const fn with_read_jitter(mut self, window: Duration) -> Self {
        self.read_jitter = window;
        self
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
        let died = || io::Error::other("a store connection thread died");
        let window = u64::try_from(self.read_jitter.as_nanos()).unwrap_or(u64::MAX);
        if !matches!(job, Job::Read { .. }) || window == 0 {
            return worker.send(job).map_err(|_| died());
        }
        let delay = Duration::from_nanos(rand::rng().random_range(0..window));
        let delayed = Delayed {
            due: Instant::now()
                .checked_add(delay)
                .unwrap_or_else(Instant::now),
            to: worker.clone(),
            job,
        };
        let timer = self.timer.get_or_insert_with(|| {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || run_timer(&rx));
            tx
        });
        timer.send(delayed).map_err(|_| died())
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
            cover: false,
        };
        self.send(isolation_key(&at.stream), job)
    }

    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        self.send(
            isolation_key(&at.stream),
            Job::Read {
                at: *at,
                done: done.clone(),
                tries: 0,
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
                tries: 0,
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
                cover: true,
            },
        )
    }
}

/// A read waiting for its moment.
struct Delayed {
    due: Instant,
    to: Sender<Job>,
    job: Job,
}

/// Hand each delayed read to its connection when it's due. When the transport is dropped,
/// whatever is still waiting goes out at once.
fn run_timer(delayed: &Receiver<Delayed>) {
    let mut queue: BinaryHeap<Reverse<(Instant, u64)>> = BinaryHeap::new();
    let mut waiting: HashMap<u64, (Sender<Job>, Job)> = HashMap::new();
    let mut next_id: u64 = 0;
    loop {
        while let Some(&Reverse((due, id))) = queue.peek() {
            if due > Instant::now() {
                break;
            }
            queue.pop();
            if let Some((to, job)) = waiting.remove(&id) {
                to.send(job).ok();
            }
        }
        let arrived = match queue.peek() {
            Some(&Reverse((due, _))) => {
                delayed.recv_timeout(due.saturating_duration_since(Instant::now()))
            }
            None => delayed.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match arrived {
            Ok(Delayed { due, to, job }) => {
                queue.push(Reverse((due, next_id)));
                waiting.insert(next_id, (to, job));
                next_id = next_id.wrapping_add(1);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                for (to, job) in waiting.into_values() {
                    to.send(job).ok();
                }
                return;
            }
        }
    }
}

/// One connection's thread. It sends every job waiting (up to [`MAX_BATCH`]) before reading
/// the answers, which come back in order, so one round trip through the circuit carries
/// many requests. Jobs without an answer are retried after a backoff, reconnecting first.
fn work(key: &str, dialer: &Dialer, retry: Retry, jobs: &Receiver<Job>) {
    let mut conn = None;
    let mut retrying: Vec<Job> = Vec::new();
    let mut wait = retry.first;
    loop {
        let mut batch = std::mem::take(&mut retrying);
        if batch.is_empty() {
            match jobs.recv() {
                Ok(job) => batch.push(job),
                Err(_) => return,
            }
        }
        while batch.len() < MAX_BATCH {
            match jobs.try_recv() {
                Ok(job) => batch.push(job),
                Err(_) => break,
            }
        }
        let answered = run_batch(&mut conn, dialer, key, &batch);
        let unanswered = batch.split_off(answered.min(batch.len()));
        if unanswered.is_empty() {
            wait = retry.first;
            continue;
        }
        conn = None;
        retrying = unanswered.into_iter().filter_map(Job::failed).collect();
        if !retrying.is_empty() {
            eprintln!("purple-net: the store didn't answer; retrying in {wait:?}");
            thread::sleep(wait);
            wait = wait.saturating_mul(2).min(retry.max);
        }
    }
}

/// Send every job's request, then read answers in order. Returns how many jobs were
/// answered before the connection failed or answered wrongly.
fn run_batch(conn: &mut Option<Box<dyn Conn>>, dialer: &Dialer, key: &str, batch: &[Job]) -> usize {
    let c = match conn {
        Some(c) => c,
        None => match dialer.current().dial(key) {
            Ok(fresh) => conn.insert(fresh),
            Err(err) => {
                eprintln!("purple-net: can't reach the store: {err}");
                return 0;
            }
        },
    };
    let sent = batch
        .iter()
        .try_for_each(|job| job.request().write_to(c))
        .and_then(|()| c.flush());
    if sent.is_err() {
        return 0;
    }
    let mut answered: usize = 0;
    for job in batch {
        let Ok(Some(answer)) = ProviderMsg::read_from(c) else {
            break;
        };
        if !job.answer(answer) {
            break;
        }
        answered = answered.saturating_add(1);
    }
    answered
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
        /// When each dial happened.
        dial_times: Mutex<Vec<Instant>>,
        /// One-way delay on every byte, like a circuit's.
        latency: Option<Duration>,
    }

    /// Copy `from` to `to`, delivering each chunk `delay` after it was read.
    fn delayed_copy(mut from: UnixStream, mut to: UnixStream, delay: Duration) {
        let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = from.read(&mut buf) {
                if tx.send((Instant::now(), buf[..n].to_vec())).is_err() {
                    return;
                }
            }
        });
        thread::spawn(move || {
            for (at, bytes) in rx {
                thread::sleep(delay.saturating_sub(at.elapsed()));
                if to.write_all(&bytes).is_err() {
                    return;
                }
            }
        });
    }

    impl Dial for MemDial {
        fn dial(&self, isolation: &str) -> io::Result<Box<dyn Conn>> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.dial_times
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Instant::now());
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
            if let Some(delay) = self.latency {
                let (near, far) = UnixStream::pair()?;
                delayed_copy(theirs.try_clone()?, far.try_clone()?, delay);
                delayed_copy(far, theirs, delay);
                theirs = near;
            }
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

    fn next(rx: &Receiver<Done>) -> Done {
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
    fn requests_on_one_stream_share_round_trips() {
        let dial = Arc::new(MemDial {
            latency: Some(Duration::from_millis(100)),
            ..MemDial::default()
        });
        let mut t = net(&dial);
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for i in 0..20 {
            t.read(&at(1, i), &tx).unwrap();
        }
        for _ in 0..20 {
            next(&rx);
        }
        // One at a time would take 20 round trips of 200 ms.
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn reads_leave_at_independent_random_times() {
        let dial = Arc::new(MemDial::default());
        let mut t = net(&dial).with_read_jitter(Duration::from_millis(400));
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        for stream in 0..10 {
            t.read(&at(stream, 0), &tx).unwrap();
        }
        for _ in 0..10 {
            next(&rx);
        }
        let times = dial.dial_times.lock().unwrap().clone();
        let first = times.iter().min().unwrap().duration_since(start);
        let last = times.iter().max().unwrap().duration_since(start);
        // Ten reads asked for at once reach ten circuits spread over the window, so the
        // store can't group them by when they arrive.
        assert!(
            last.saturating_sub(first) >= Duration::from_millis(100),
            "{first:?}..{last:?}"
        );
        assert!(last < Duration::from_secs(1), "{last:?}");
    }

    #[test]
    fn cover_writes_are_sent_once() {
        let dial = Arc::new(MemDial::default());
        dial.refuse.store(true, Ordering::SeqCst);
        let mut t = net(&dial);
        t.cover().unwrap();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(dial.dials.load(Ordering::SeqCst), 1, "no retries for cover");
    }

    #[test]
    fn a_silent_tor_times_out() {
        let path = std::env::temp_dir().join(format!("purple-silent-{}", std::process::id()));
        std::fs::remove_file(&path).ok();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let hold = thread::spawn(move || listener.accept().map(|(c, _)| c));
        let dial = OnionDial {
            socks: path,
            host: "x.onion".into(),
            port: 80,
            timeout: Duration::from_millis(100),
        };
        let start = Instant::now();
        assert!(dial.dial("k").is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(hold);
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
