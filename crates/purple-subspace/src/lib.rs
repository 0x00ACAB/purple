//! Transports that store and fetch boxes, plus the cover-traffic [`scheduler`].
//!
//! purple's transport abstraction is a box store: every packet goes into its own
//! write-once box, addressed by a stream seed and an index. Pigeonhole provides this
//! natively; anything else (the dev provider here, or a Nym-based provider) stores one
//! packet per derived box address. A transport turns (seed, index) into an address with a
//! one-way function, so whoever stores the boxes can't tell which ones form a stream.
//!
//! Reads and writes can take seconds on a mixnet, so they report back through a [`Sink`]
//! rather than returning, and many can be in flight at once.

pub mod katzenpost;
pub mod noise;
pub mod scheduler;
pub mod tor;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use purple_combadge::{BoxRef, PACKET_LEN, Packet, SEED_LEN, StreamSeed, read_frame, write_frame};
use rand::{Rng, RngCore};
use sha2::Sha256;

/// What reading a box found: `None` if it hasn't been written or has expired.
#[derive(Debug)]
pub struct ReadDone {
    /// The box read.
    pub at: BoxRef,
    /// What it held, or why the read failed.
    pub packet: io::Result<Option<Packet>>,
}

/// What a transport reports back.
#[derive(Debug)]
pub enum Done {
    /// A read finished.
    Read(ReadDone),
    /// A write reached the store, so the box now holds the packet.
    Written(BoxRef),
    /// A write found its box already holding a packet, so nothing changed.
    Taken(BoxRef),
}

/// Where a transport reports finished reads and writes.
pub type Sink = Sender<Done>;

/// Stores and fetches write-once boxes.
pub trait Transport {
    /// Write `packet` into box `at`. Writing a box that already holds a packet changes nothing.
    /// May return before the write reaches the network; once the network has answered,
    /// [`Done::Written`] or [`Done::Taken`] goes to `done`, if given. A write that never lands is never reported.
    ///
    /// # Errors
    /// Fails if the packet can't be handed to the network.
    fn write(&mut self, at: &BoxRef, packet: Packet, done: Option<&Sink>) -> io::Result<()>;

    /// Start reading box `at`. The result goes to `done`, possibly before this returns.
    ///
    /// # Errors
    /// Fails if the network can't be reached.
    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()>;

    /// Read box `at` for padding: nobody wants what it holds, so a transport with several
    /// connections may use any of them. The answer goes to `done` like a read's.
    ///
    /// # Errors
    /// Fails if the network can't be reached.
    fn read_cover(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        self.read(at, done)
    }

    /// Fill one slot of the cover stream with no real packet to send. The default writes
    /// random bytes to a random box, which looks like a sealed real packet.
    ///
    /// # Errors
    /// Fails if the packet can't be handed to the network.
    fn cover(&mut self) -> io::Result<()> {
        let (at, packet) = random_box()?;
        self.write(&at, packet, None)
    }

    /// Finish writes still in flight before the process exits.
    ///
    /// # Errors
    /// Fails if they can't be finished.
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Random bytes for a random box: indistinguishable from a sealed real packet.
///
/// # Errors
/// Can't fail in practice; the packet length is always right.
pub fn random_box() -> io::Result<(BoxRef, Packet)> {
    let mut rng = rand::rng();
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);
    let at = BoxRef {
        stream: StreamSeed(seed),
        index: rng.random(),
    };
    let mut bytes = vec![0u8; PACKET_LEN];
    rng.fill_bytes(&mut bytes);
    Packet::from_slice(&bytes).map(|packet| (at, packet))
}

/// Where a box lives at a provider. Unlinkable to its stream without the seed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxAddr(pub [u8; 32]);

impl std::fmt::Debug for BoxAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoxAddr(..)")
    }
}

/// The provider address of box `at`: HKDF keyed by the stream seed, over the index.
#[must_use]
pub fn box_address(at: &BoxRef) -> BoxAddr {
    let mut addr = [0u8; 32];
    // A 32-byte output is always within HKDF-SHA256's limit, so this can't fail.
    Hkdf::<Sha256>::new(Some(b"purple box address v1"), &at.stream.0)
        .expand(&at.index.to_be_bytes(), &mut addr)
        .ok();
    BoxAddr(addr)
}

/// Somewhere to keep boxes: [`BoxStore`] in memory, or purple-memory-alpha's disk store.
pub trait Boxes: Send + Sync {
    /// Store `packet` at `addr` unless something live is already there. Returns whether
    /// it was stored.
    ///
    /// # Errors
    /// Fails if the store can't be written.
    fn put(&self, addr: BoxAddr, packet: Packet) -> io::Result<bool>;

    /// The packet at `addr`, if any.
    ///
    /// # Errors
    /// Fails if the store can't be read.
    fn get(&self, addr: &BoxAddr) -> io::Result<Option<Packet>>;
}

impl Boxes for BoxStore {
    fn put(&self, addr: BoxAddr, packet: Packet) -> io::Result<bool> {
        Self::put(self, addr, packet)
    }

    fn get(&self, addr: &BoxAddr) -> io::Result<Option<Packet>> {
        Self::get(self, addr)
    }
}

/// Write-once boxes in memory, with optional expiry. Clones share one store. Used by the
/// in-memory network and by `purple-holodeck`.
#[derive(Clone, Debug, Default)]
pub struct BoxStore {
    inner: Arc<Mutex<StoreInner>>,
}

#[derive(Debug, Default)]
struct StoreInner {
    boxes: HashMap<BoxAddr, (Instant, Packet)>,
    retention: Option<Duration>,
    writes: u64,
}

/// How many writes between sweeps for expired boxes.
const SWEEP_EVERY: u64 = 1024;

impl BoxStore {
    /// A store that forgets boxes older than `retention`. Cover traffic writes boxes nobody
    /// reads, so without a limit they pile up forever.
    #[must_use]
    pub fn with_retention(retention: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                retention: Some(retention),
                ..StoreInner::default()
            })),
        }
    }

    /// Store `packet` at `addr` unless something is already there. Returns whether it was
    /// stored.
    ///
    /// # Errors
    /// Fails only if the lock is poisoned.
    pub fn put(&self, addr: BoxAddr, packet: Packet) -> io::Result<bool> {
        let mut inner = self.inner.lock().map_err(poisoned)?;
        let now = Instant::now();
        let retention = inner.retention;
        let stored = inner
            .boxes
            .get(&addr)
            .is_none_or(|(at, _)| expired(retention, *at, now));
        if stored {
            inner.boxes.insert(addr, (now, packet));
        }
        inner.writes = inner.writes.wrapping_add(1);
        if inner.writes.is_multiple_of(SWEEP_EVERY) {
            inner
                .boxes
                .retain(|_, (at, _)| !expired(retention, *at, now));
        }
        drop(inner);
        Ok(stored)
    }

    /// The packet at `addr`, if it's there and hasn't expired.
    ///
    /// # Errors
    /// Fails only if the lock is poisoned.
    pub fn get(&self, addr: &BoxAddr) -> io::Result<Option<Packet>> {
        let inner = self.inner.lock().map_err(poisoned)?;
        let now = Instant::now();
        let found = inner
            .boxes
            .get(addr)
            .filter(|(stored, _)| !expired(inner.retention, *stored, now))
            .map(|(_, packet)| packet.clone());
        drop(inner);
        Ok(found)
    }
}

fn expired(retention: Option<Duration>, stored: Instant, now: Instant) -> bool {
    retention.is_some_and(|retention| now.saturating_duration_since(stored) > retention)
}

/// In-memory stand-in for the network: a [`BoxStore`] addressed through [`box_address`].
/// Clones share one network, so two clones behave like two clients of the same providers.
#[derive(Clone, Debug, Default)]
pub struct FakeTransport {
    store: BoxStore,
}

impl FakeTransport {
    /// A network whose boxes expire after `retention`.
    #[must_use]
    pub fn with_retention(retention: Duration) -> Self {
        Self {
            store: BoxStore::with_retention(retention),
        }
    }
}

impl Transport for FakeTransport {
    fn write(&mut self, at: &BoxRef, packet: Packet, done: Option<&Sink>) -> io::Result<()> {
        let stored = self.store.put(box_address(at), packet)?;
        report_write(done, at, stored);
        Ok(())
    }

    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        let packet = self.store.get(&box_address(at));
        report(done, at, packet);
        Ok(())
    }
}

/// Messages between `purple-subspace` and `purple-holodeck`. Only box addresses cross this
/// link, never stream seeds or indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderMsg {
    /// Store a packet.
    Put {
        /// Where.
        addr: BoxAddr,
        /// What.
        packet: Packet,
    },
    /// Ask for a box. Answered by `Found` or `Empty`.
    Get {
        /// Which box.
        addr: BoxAddr,
    },
    /// The box holds this packet.
    Found {
        /// Which box.
        addr: BoxAddr,
        /// Its contents.
        packet: Packet,
    },
    /// The box is empty or expired.
    Empty {
        /// Which box.
        addr: BoxAddr,
    },
    /// The put was stored.
    Stored {
        /// Which box.
        addr: BoxAddr,
    },
    /// The box already held a packet, so the put changed nothing.
    Taken {
        /// Which box.
        addr: BoxAddr,
    },
}

const MAX_PROVIDER_FRAME: usize = 1 + 32 + PACKET_LEN;
const TAG_PUT: u8 = 1;
const TAG_GET: u8 = 2;
const TAG_FOUND: u8 = 3;
const TAG_EMPTY: u8 = 4;
const TAG_STORED: u8 = 5;
const TAG_TAKEN: u8 = 6;

impl ProviderMsg {
    /// Write as one frame: tag, address, then the packet if there is one. A reply without
    /// a packet carries zeros in its place, so every reply is the same length and someone
    /// watching the client's link can't tell a box that turned up from an empty one.
    ///
    /// # Errors
    /// Fails if the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        const PADDING: [u8; PACKET_LEN] = [0; PACKET_LEN];
        let (tag, addr, body): (_, _, &[u8]) = match self {
            Self::Put { addr, packet } => (TAG_PUT, addr, packet.as_bytes()),
            Self::Get { addr } => (TAG_GET, addr, &[]),
            Self::Found { addr, packet } => (TAG_FOUND, addr, packet.as_bytes()),
            Self::Empty { addr } => (TAG_EMPTY, addr, &PADDING),
            Self::Stored { addr } => (TAG_STORED, addr, &PADDING),
            Self::Taken { addr } => (TAG_TAKEN, addr, &PADDING),
        };
        let mut out = Vec::with_capacity(MAX_PROVIDER_FRAME);
        out.push(tag);
        out.extend_from_slice(&addr.0);
        out.extend_from_slice(body);
        write_frame(w, &out, MAX_PROVIDER_FRAME)
    }

    /// Read one message. `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error or a malformed message.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let Some(frame) = read_frame(r, MAX_PROVIDER_FRAME)? else {
            return Ok(None);
        };
        let (&tag, rest) = frame
            .split_first()
            .ok_or_else(|| invalid("empty message"))?;
        let (addr, body) = rest
            .split_first_chunk::<32>()
            .ok_or_else(|| invalid("message too short"))?;
        let addr = BoxAddr(*addr);
        let msg = match tag {
            TAG_PUT => Self::Put {
                addr,
                packet: Packet::from_slice(body)?,
            },
            TAG_FOUND => Self::Found {
                addr,
                packet: Packet::from_slice(body)?,
            },
            TAG_GET if !body.is_empty() => return Err(invalid("trailing bytes")),
            TAG_EMPTY | TAG_STORED | TAG_TAKEN
                if body.len() != PACKET_LEN || body.iter().any(|&b| b != 0) =>
            {
                return Err(invalid("reply isn't padded to a packet's length"));
            }
            TAG_GET => Self::Get { addr },
            TAG_EMPTY => Self::Empty { addr },
            TAG_STORED => Self::Stored { addr },
            TAG_TAKEN => Self::Taken { addr },
            _ => return Err(invalid("unknown message tag")),
        };
        Ok(Some(msg))
    }
}

/// Answer one client's `Put`/`Get` requests from `store` until it disconnects. With
/// `writes_per_sec`, a client writing faster than that is slowed down.
///
/// # Errors
/// Fails on an I/O error or a message only the provider may send.
pub fn serve_provider(
    peer: &mut (impl Read + Write),
    store: &impl Boxes,
    writes_per_sec: Option<u32>,
) -> io::Result<()> {
    let mut bucket = writes_per_sec.map(TokenBucket::new);
    while let Some(msg) = ProviderMsg::read_from(peer)? {
        match msg {
            ProviderMsg::Put { addr, packet } => {
                if let Some(bucket) = &mut bucket {
                    bucket.take();
                }
                let reply = if store.put(addr, packet)? {
                    ProviderMsg::Stored { addr }
                } else {
                    ProviderMsg::Taken { addr }
                };
                reply.write_to(peer)?;
            }
            ProviderMsg::Get { addr } => match store.get(&addr)? {
                Some(packet) => ProviderMsg::Found { addr, packet }.write_to(peer)?,
                None => ProviderMsg::Empty { addr }.write_to(peer)?,
            },
            ProviderMsg::Found { .. }
            | ProviderMsg::Empty { .. }
            | ProviderMsg::Stored { .. }
            | ProviderMsg::Taken { .. } => {
                return Err(invalid("client sent a message only the provider may send"));
            }
        }
        peer.flush()?;
    }
    Ok(())
}

/// Lets `rate` writes through per second, with a burst of `rate`; past that, `take` sleeps.
#[derive(Debug)]
struct TokenBucket {
    rate: u32,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        Self {
            rate,
            tokens: f64::from(rate),
            last: Instant::now(),
        }
    }

    fn take(&mut self) {
        let now = Instant::now();
        let rate = f64::from(self.rate);
        self.tokens = now
            .duration_since(self.last)
            .as_secs_f64()
            .mul_add(rate, self.tokens)
            .min(rate);
        self.last = now;
        if self.tokens < 1.0 {
            std::thread::sleep(Duration::from_secs_f64((1.0 - self.tokens) / rate));
            self.tokens = 1.0;
            self.last = Instant::now();
        }
        self.tokens -= 1.0;
    }
}

/// Forwards to a `purple-holodeck` over TCP. Development only: there is no mixnet in
/// between, so the provider sees which client reads and writes which boxes.
#[derive(Debug)]
pub struct DevProviderTransport {
    stream: TcpStream,
}

impl DevProviderTransport {
    /// Connect to the dev provider at `addr`.
    ///
    /// # Errors
    /// Fails if the connection fails.
    pub fn connect(addr: &str) -> io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr)?,
        })
    }
}

impl Transport for DevProviderTransport {
    fn write(&mut self, at: &BoxRef, packet: Packet, done: Option<&Sink>) -> io::Result<()> {
        let addr = box_address(at);
        ProviderMsg::Put { addr, packet }.write_to(&mut self.stream)?;
        let stored = match ProviderMsg::read_from(&mut self.stream)? {
            Some(ProviderMsg::Stored { addr: got }) if got == addr => true,
            Some(ProviderMsg::Taken { addr: got }) if got == addr => false,
            Some(_) => return Err(invalid("unexpected reply from the dev provider")),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "dev provider closed the connection",
                ));
            }
        };
        report_write(done, at, stored);
        Ok(())
    }

    fn read(&mut self, at: &BoxRef, done: &Sink) -> io::Result<()> {
        let packet = self.fetch(at)?;
        report(done, at, Ok(packet));
        Ok(())
    }
}

impl DevProviderTransport {
    fn fetch(&mut self, at: &BoxRef) -> io::Result<Option<Packet>> {
        let addr = box_address(at);
        ProviderMsg::Get { addr }.write_to(&mut self.stream)?;
        match ProviderMsg::read_from(&mut self.stream)? {
            Some(ProviderMsg::Found { addr: got, packet }) if got == addr => Ok(Some(packet)),
            Some(ProviderMsg::Empty { addr: got }) if got == addr => Ok(None),
            Some(_) => Err(invalid("unexpected reply from the dev provider")),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "dev provider closed the connection",
            )),
        }
    }
}

/// Hand a finished read to `done`. If nobody listens any more, the read is moot.
pub(crate) fn report(done: &Sink, at: &BoxRef, packet: io::Result<Option<Packet>>) {
    done.send(Done::Read(ReadDone { at: *at, packet })).ok();
}

/// Tell `done`, if given, how the write to box `at` went.
pub(crate) fn report_write(done: Option<&Sink>, at: &BoxRef, stored: bool) {
    if let Some(done) = done {
        let report = if stored {
            Done::Written(*at)
        } else {
            Done::Taken(*at)
        };
        done.send(report).ok();
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn poisoned<T>(_: PoisonError<T>) -> io::Error {
    io::Error::other("box store lock poisoned")
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    /// Read a box through a transport that reports before `read` returns.
    fn read_now(net: &mut impl Transport, at: &BoxRef) -> Option<Packet> {
        let (tx, rx) = mpsc::channel();
        net.read(at, &tx).unwrap();
        match rx.try_recv().unwrap() {
            Done::Read(done) => {
                assert_eq!(done.at, *at);
                done.packet.unwrap()
            }
            Done::Written(_) | Done::Taken(_) => panic!("a read reported a write"),
        }
    }

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    fn at(seed: u8, index: u64) -> BoxRef {
        BoxRef {
            stream: StreamSeed([seed; SEED_LEN]),
            index,
        }
    }

    fn framed(msg: &ProviderMsg) -> Vec<u8> {
        let mut out = Vec::new();
        msg.write_to(&mut out).unwrap();
        out
    }

    #[test]
    fn every_store_reply_is_the_same_length() {
        let addr = BoxAddr([3; 32]);
        let found = framed(&ProviderMsg::Found {
            addr,
            packet: packet(1),
        });
        for reply in [
            ProviderMsg::Empty { addr },
            ProviderMsg::Stored { addr },
            ProviderMsg::Taken { addr },
        ] {
            let bytes = framed(&reply);
            assert_eq!(bytes.len(), found.len(), "{reply:?}");
            assert_eq!(
                ProviderMsg::read_from(&mut bytes.as_slice()).unwrap(),
                Some(reply)
            );
        }
    }

    #[test]
    fn an_unpadded_or_badly_padded_reply_is_refused() {
        let mut short = vec![TAG_EMPTY];
        short.extend_from_slice(&[3; 32]);
        let mut frame = Vec::new();
        write_frame(&mut frame, &short, MAX_PROVIDER_FRAME).unwrap();
        assert!(ProviderMsg::read_from(&mut frame.as_slice()).is_err());

        let mut dirty = short;
        dirty.extend_from_slice(&[1; PACKET_LEN]);
        let mut dirty_frame = Vec::new();
        write_frame(&mut dirty_frame, &dirty, MAX_PROVIDER_FRAME).unwrap();
        assert!(ProviderMsg::read_from(&mut dirty_frame.as_slice()).is_err());
    }

    #[test]
    fn provider_serves_through_noise() {
        let (private, public) = noise::noise_keypair().unwrap();
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let store = BoxStore::default();
        let server_store = store.clone();
        let server = std::thread::spawn(move || {
            let mut s = noise::NoiseStream::server(b, &private).unwrap();
            serve_provider(&mut s, &server_store, None).unwrap();
        });
        let mut c = noise::NoiseStream::client(a, &public).unwrap();
        let addr = BoxAddr([3; 32]);
        ProviderMsg::Put {
            addr,
            packet: packet(1),
        }
        .write_to(&mut c)
        .unwrap();
        c.flush().unwrap();
        assert_eq!(
            ProviderMsg::read_from(&mut c).unwrap(),
            Some(ProviderMsg::Stored { addr })
        );
        drop(c);
        server.join().unwrap();
        assert_eq!(store.get(&addr).unwrap(), Some(packet(1)));
    }

    #[test]
    fn write_rate_is_limited_per_connection() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let store = BoxStore::default();
        let server = std::thread::spawn(move || serve_provider(&mut b, &store, Some(10)));
        let start = Instant::now();
        for i in 0..25u8 {
            ProviderMsg::Put {
                addr: BoxAddr([i; 32]),
                packet: packet(i),
            }
            .write_to(&mut a)
            .unwrap();
            ProviderMsg::read_from(&mut a).unwrap().unwrap();
        }
        // 10 free, then 15 more at 10/s.
        assert!(
            start.elapsed() >= Duration::from_millis(1400),
            "{:?}",
            start.elapsed()
        );
        drop(a);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn cover_reads_answer_like_reads() {
        let mut net = FakeTransport::default();
        net.write(&at(6, 0), packet(4), None).unwrap();
        let (tx, rx) = mpsc::channel();
        net.read_cover(&at(6, 0), &tx).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(Done::Read(ReadDone {
                packet: Ok(Some(_)),
                ..
            }))
        ));
    }

    #[test]
    fn boxes_are_write_once_and_reads_do_not_consume() {
        let mut net = FakeTransport::default();
        let (tx, rx) = mpsc::channel();
        net.write(&at(1, 0), packet(1), Some(&tx)).unwrap();
        net.write(&at(1, 0), packet(2), Some(&tx)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Done::Written(got)) if got == at(1, 0)));
        assert!(matches!(rx.try_recv(), Ok(Done::Taken(got)) if got == at(1, 0)));
        assert_eq!(read_now(&mut net, &at(1, 0)), Some(packet(1)));
        assert_eq!(read_now(&mut net, &at(1, 0)), Some(packet(1)));
        assert_eq!(read_now(&mut net, &at(1, 1)), None);
        assert_eq!(read_now(&mut net, &at(2, 0)), None);
    }

    #[test]
    fn writes_report_when_asked() {
        let mut net = FakeTransport::default();
        let (tx, rx) = mpsc::channel();
        net.write(&at(4, 0), packet(1), Some(&tx)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Done::Written(got)) if got == at(4, 0)));
        net.cover().unwrap();
        assert!(rx.try_recv().is_err(), "cover writes aren't reported");
    }

    #[test]
    fn box_addresses_hide_the_stream() {
        let a0 = box_address(&at(1, 0));
        let a1 = box_address(&at(1, 1));
        let b0 = box_address(&at(2, 0));
        assert_ne!(a0, a1);
        assert_ne!(a0, b0);
        assert_eq!(a0, box_address(&at(1, 0)));
        // Nothing of the seed or index shows in the address.
        assert!(!a0.0.windows(4).any(|w| w == [1, 1, 1, 1]));
    }

    #[test]
    fn clones_share_one_network() {
        let mut alice = FakeTransport::default();
        let mut bob = alice.clone();
        alice.write(&at(3, 0), packet(7), None).unwrap();
        assert_eq!(read_now(&mut bob, &at(3, 0)), Some(packet(7)));
    }

    #[test]
    fn expired_boxes_read_as_empty_and_can_be_rewritten() {
        let store = BoxStore::with_retention(Duration::ZERO);
        let addr = BoxAddr([5; 32]);
        store.put(addr, packet(1)).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(store.get(&addr).unwrap(), None);
        store.put(addr, packet(2)).unwrap();

        let lasting = BoxStore::with_retention(Duration::from_hours(1));
        lasting.put(addr, packet(3)).unwrap();
        assert_eq!(lasting.get(&addr).unwrap(), Some(packet(3)));
    }

    #[test]
    fn sweeps_expired_boxes() {
        let store = BoxStore::with_retention(Duration::ZERO);
        for i in 0..SWEEP_EVERY {
            let mut addr = [0u8; 32];
            addr[..8].copy_from_slice(&i.to_be_bytes());
            store.put(BoxAddr(addr), packet(0)).unwrap();
        }
        assert!(store.inner.lock().unwrap().boxes.len() < 2);
    }

    #[test]
    fn dev_provider_transport_round_trips_through_serve_provider() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let store = BoxStore::default();
        let server_store = store.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_provider(&mut stream, &server_store, None).unwrap();
        });
        let mut client = DevProviderTransport::connect(&addr).unwrap();
        client.write(&at(4, 0), packet(1), None).unwrap();
        client.write(&at(4, 1), packet(2), None).unwrap();
        let (tx, rx) = mpsc::channel();
        client.write(&at(4, 0), packet(9), Some(&tx)).unwrap();
        assert!(matches!(rx.try_recv(), Ok(Done::Taken(got)) if got == at(4, 0)));
        assert_eq!(read_now(&mut client, &at(4, 0)), Some(packet(1)));
        assert_eq!(read_now(&mut client, &at(4, 1)), Some(packet(2)));
        assert_eq!(read_now(&mut client, &at(4, 2)), None);
        drop(client);
        server.join().unwrap();
        // The provider only ever saw derived addresses.
        assert!(store.get(&box_address(&at(4, 0))).unwrap().is_some());
    }

    #[test]
    fn provider_messages_reject_garbage() {
        let mut frame = Vec::new();
        write_frame(&mut frame, &[99; 33], MAX_PROVIDER_FRAME).unwrap();
        assert!(ProviderMsg::read_from(&mut &frame[..]).is_err());
        let mut trailing = Vec::new();
        let mut body = vec![TAG_GET];
        body.extend_from_slice(&[0; 33]);
        write_frame(&mut trailing, &body, MAX_PROVIDER_FRAME).unwrap();
        assert!(ProviderMsg::read_from(&mut &trailing[..]).is_err());
    }
}
