//! Messages between purple's processes, and the framing that carries them. Messages
//! between `purple-data` and `purple-subspace` are here; those with `purple-lcars` are in [`ui`].
//!
//! Every message has a fixed layout and the decoder rejects anything else: unknown tags,
//! wrong lengths, oversized frames. Keep it that way, since `purple-data` parses these
//! straight from the process that faces the network.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Messages between purple-data and purple-cloak or the launcher.
pub mod torctl;
pub mod ui;

/// Size of every packet (one box). Must fit the transport's box payload: Namenlos boxes
/// hold 1549 bytes, and `purple-subspace` checks the daemon's geometry when it connects.
pub const PACKET_LEN: usize = 1536;
/// Size of a stream seed.
pub const SEED_LEN: usize = 32;

/// Fd where `purple-lcars` finds its socket to `purple-data`.
pub const UI_CORE_FD: RawFd = 3;
/// Fd where `purple-data` finds its socket to `purple-lcars`.
pub const CORE_UI_FD: RawFd = 3;
/// Fd where `purple-data` finds its socket to `purple-subspace`.
pub const CORE_NET_FD: RawFd = 4;
/// Fd where `purple-subspace` finds its socket to `purple-data`.
pub const NET_CORE_FD: RawFd = 3;
/// Fd where `purple-cloak` finds its socket to `purple-data`.
pub const TORCTL_CORE_FD: RawFd = 3;
/// Fd where `purple-data` finds its socket to `purple-cloak`, when started with `--torctl`.
pub const CORE_TORCTL_FD: RawFd = 5;
/// Fd where `purple-data` finds its socket to the launcher, when started with `--torctl`.
pub const CORE_LAUNCHER_FD: RawFd = 6;

const MAX_NET_FRAME: usize = 1 + SEED_LEN + 8 + PACKET_LEN;

const TAG_WRITE: u8 = 1;
const TAG_READ: u8 = 2;
const TAG_FOUND: u8 = 3;
const TAG_EMPTY: u8 = 4;
const TAG_WRITTEN: u8 = 5;
const TAG_TAKEN: u8 = 6;
const TAG_READ_COVER: u8 = 7;
// Tags 8 and 9 were Status and Choose, now purple-cloak's (see torctl.rs).
const TAG_USE_DIRECT: u8 = 10;

/// Longest bridge text the user may paste: a few bridge lines.
pub const MAX_BRIDGE_TEXT: usize = 1400;

/// How purple-subspace reaches the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Tor with no bridge.
    Tor,
    /// Tor over the built-in obfs4 bridges.
    Obfs4,
    /// Tor over Snowflake.
    Snowflake,
    /// Tor over the built-in webtunnel bridges.
    WebTunnel,
    /// Tor over bridge lines the user pasted.
    Pasted,
    /// Straight to the store, without Tor.
    Direct,
}

impl Route {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Tor => 0,
            Self::Obfs4 => 1,
            Self::Snowflake => 2,
            Self::WebTunnel => 3,
            Self::Pasted => 4,
            Self::Direct => 5,
        }
    }

    /// The route with wire code `code`.
    ///
    /// # Errors
    /// Fails on an unknown code.
    pub fn from_code(code: u8) -> io::Result<Self> {
        Ok(match code {
            0 => Self::Tor,
            1 => Self::Obfs4,
            2 => Self::Snowflake,
            3 => Self::WebTunnel,
            4 => Self::Pasted,
            5 => Self::Direct,
            _ => return Err(invalid("unknown route")),
        })
    }
}

/// What purple-subspace tells core about its connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetStatus {
    /// Bootstrapping over `route`, `percent` done.
    Connecting {
        /// The route being tried.
        route: Route,
        /// Tor's bootstrap progress, 0 to 100.
        percent: u8,
    },
    /// Connected over `route`.
    Connected {
        /// The route in use.
        route: Route,
    },
    /// Every automatic route failed; the user has to choose.
    Blocked,
}

impl NetStatus {
    /// Wire form: kind, route code, percent.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 3] {
        match self {
            Self::Connecting { route, percent } => [0, route.code(), percent],
            Self::Connected { route } => [1, route.code(), 0],
            Self::Blocked => [2, 0, 0],
        }
    }

    /// Parse the wire form.
    ///
    /// # Errors
    /// Fails on an unknown kind or route, or a percent over 100.
    pub fn from_bytes([kind, route, percent]: [u8; 3]) -> io::Result<Self> {
        if percent > 100 {
            return Err(invalid("percent over 100"));
        }
        let route = Route::from_code(route)?;
        Ok(match kind {
            0 => Self::Connecting { route, percent },
            1 => Self::Connected { route },
            2 => Self::Blocked,
            _ => return Err(invalid("unknown status")),
        })
    }
}

/// What the user chose after [`NetStatus::Blocked`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetChoice {
    /// Connect to the store without Tor, until purple exits.
    Direct,
    /// Try these bridge lines, one per line.
    Bridges(String),
}

/// Identifies one append-only stream of boxes to the transport.
///
/// `purple-data` derives it one-way from a queue secret, so the transport can address boxes
/// but can't derive the key that seals their contents. Each transport maps (seed, index) to
/// its own box addresses.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamSeed(pub [u8; SEED_LEN]);

impl fmt::Debug for StreamSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StreamSeed(..)")
    }
}

/// One box: a position in a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BoxRef {
    /// The stream.
    pub stream: StreamSeed,
    /// Position in the stream, from 0.
    pub index: u64,
}

/// One fixed-size packet. Its contents are opaque to everything but `purple-data`.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet(Box<[u8; PACKET_LEN]>);

impl Packet {
    /// Wrap exactly [`PACKET_LEN`] bytes.
    ///
    /// # Errors
    /// Fails if `bytes` is any other length.
    pub fn from_slice(bytes: &[u8]) -> io::Result<Self> {
        let array: [u8; PACKET_LEN] = bytes
            .try_into()
            .map_err(|_| invalid("packet has the wrong length"))?;
        Ok(Self(Box::new(array)))
    }

    /// The packet's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PACKET_LEN] {
        &self.0
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Packet(..)")
    }
}

/// Messages between `purple-data` and `purple-subspace`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetMsg {
    /// core to net: write `packet` into box `at`. Boxes are write-once.
    Write {
        /// The box.
        at: BoxRef,
        /// Its contents.
        packet: Packet,
    },
    /// core to net: read box `at`. Answered by [`NetMsg::Found`] or [`NetMsg::Empty`], in
    /// the order reads finish, not the order they were asked.
    Read {
        /// The box.
        at: BoxRef,
    },
    /// net to core: box `at` holds `packet`.
    Found {
        /// The box.
        at: BoxRef,
        /// Its contents.
        packet: Packet,
    },
    /// net to core: box `at` hasn't been written (or has expired).
    Empty {
        /// The box.
        at: BoxRef,
    },
    /// net to core: the write into box `at` landed, so core can stop keeping the packet.
    Written {
        /// The box.
        at: BoxRef,
    },
    /// net to core: box `at` already held a packet when this write arrived, so the write
    /// changed nothing. It may be core's own packet from before a restart, or someone
    /// else's; core reads the box to tell.
    Taken {
        /// The box.
        at: BoxRef,
    },
    /// core to net: a padding read of box `at`. Answered like [`NetMsg::Read`]; purple-subspace
    /// may send it over any connection, since nobody wants what it finds.
    ReadCover {
        /// The box.
        at: BoxRef,
    },
    /// core to net: the user chose direct and purple-transporter is up; switch to it.
    UseDirect,
}

impl NetMsg {
    /// Encode to the wire layout: tag, stream seed, index, then the packet if the message
    /// has one. `UseDirect` is the tag alone.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_NET_FRAME);
        let (tag, at, packet) = match self {
            Self::Write { at, packet } => (TAG_WRITE, at, Some(packet)),
            Self::Read { at } => (TAG_READ, at, None),
            Self::ReadCover { at } => (TAG_READ_COVER, at, None),
            Self::Found { at, packet } => (TAG_FOUND, at, Some(packet)),
            Self::Empty { at } => (TAG_EMPTY, at, None),
            Self::Written { at } => (TAG_WRITTEN, at, None),
            Self::Taken { at } => (TAG_TAKEN, at, None),
            Self::UseDirect => {
                out.push(TAG_USE_DIRECT);
                return out;
            }
        };
        out.push(tag);
        out.extend_from_slice(&at.stream.0);
        out.extend_from_slice(&at.index.to_be_bytes());
        if let Some(packet) = packet {
            out.extend_from_slice(packet.as_bytes());
        }
        out
    }

    /// Decode one message, rejecting anything that isn't exactly a valid layout.
    ///
    /// # Errors
    /// Fails on an unknown tag or a length that doesn't match the tag.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        match bytes {
            [TAG_USE_DIRECT] => return Ok(Self::UseDirect),
            [TAG_USE_DIRECT, ..] => return Err(invalid("use-direct takes no body")),
            _ => {}
        }
        let (&tag, rest) = bytes
            .split_first()
            .ok_or_else(|| invalid("empty message"))?;
        let (seed, rest) = rest
            .split_first_chunk::<SEED_LEN>()
            .ok_or_else(|| invalid("message too short"))?;
        let (index, body) = rest
            .split_first_chunk::<8>()
            .ok_or_else(|| invalid("message too short"))?;
        let at = BoxRef {
            stream: StreamSeed(*seed),
            index: u64::from_be_bytes(*index),
        };
        match tag {
            TAG_WRITE => Ok(Self::Write {
                at,
                packet: Packet::from_slice(body)?,
            }),
            TAG_FOUND => Ok(Self::Found {
                at,
                packet: Packet::from_slice(body)?,
            }),
            TAG_READ | TAG_READ_COVER | TAG_EMPTY | TAG_WRITTEN | TAG_TAKEN if !body.is_empty() => {
                Err(invalid("trailing bytes"))
            }
            TAG_READ => Ok(Self::Read { at }),
            TAG_READ_COVER => Ok(Self::ReadCover { at }),
            TAG_EMPTY => Ok(Self::Empty { at }),
            TAG_WRITTEN => Ok(Self::Written { at }),
            TAG_TAKEN => Ok(Self::Taken { at }),
            _ => Err(invalid("unknown message tag")),
        }
    }

    /// Write this message as one frame.
    ///
    /// # Errors
    /// Fails if the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write_frame(w, &self.encode(), MAX_NET_FRAME)
    }

    /// Read one message. Returns `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error, a truncated or oversized frame, or an invalid message.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        read_frame(r, MAX_NET_FRAME)?
            .map(|frame| Self::decode(&frame))
            .transpose()
    }
}

/// Write `body` with a 4-byte big-endian length prefix.
///
/// # Errors
/// Fails if `body` is longer than `max`, or if the write fails.
pub fn write_frame(w: &mut impl Write, body: &[u8], max: usize) -> io::Result<()> {
    if body.len() > max {
        return Err(invalid("frame too large"));
    }
    let len = u32::try_from(body.len()).map_err(|_| invalid("frame too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Read one length-prefixed frame. Returns `None` on a clean EOF before the frame starts.
///
/// # Errors
/// Fails on a read error, a truncated frame, or a length over `max`. The length is checked
/// before anything is allocated.
pub fn read_frame(r: &mut impl Read, max: usize) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let first = loop {
        match r.read(&mut header) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => break result?,
        }
    };
    match first {
        0 => return Ok(None),
        n => {
            let rest = header
                .get_mut(n..)
                .ok_or_else(|| invalid("bad read length"))?;
            r.read_exact(rest)?;
        }
    }
    let len =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| invalid("frame too large"))?;
    if len > max {
        return Err(invalid("frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Take ownership of a socket the launcher left open at `fd`.
///
/// # Errors
/// Fails if `fd` is not open or is not a socket.
///
/// # Safety
/// Nothing else in this process may own or use `fd`, and this must be called at most once
/// per fd.
#[expect(unsafe_code, reason = "adopting an fd inherited from the launcher")]
pub unsafe fn inherited_stream(fd: RawFd) -> io::Result<UnixStream> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat only reads `fd` and writes into `st`.
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "fd {fd} was not passed in: {err}"
        )));
    }
    // SAFETY: fstat succeeded, so it initialised `st`.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(invalid("inherited fd is not a socket"));
    }
    // Don't leak the socket into anything this process starts later.
    // SAFETY: fcntl on an fd that fstat just confirmed is open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the caller guarantees nothing else owns `fd`.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

pub(crate) fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    fn at(index: u64) -> BoxRef {
        BoxRef {
            stream: StreamSeed([9; SEED_LEN]),
            index,
        }
    }

    #[test]
    fn every_message_round_trips_over_a_socket() {
        let msgs = [
            NetMsg::Write {
                at: at(0),
                packet: packet(1),
            },
            NetMsg::Read { at: at(1) },
            NetMsg::Found {
                at: at(u64::MAX),
                packet: packet(2),
            },
            NetMsg::Empty { at: at(3) },
            NetMsg::Written { at: at(4) },
            NetMsg::Taken { at: at(5) },
        ];
        let (mut a, mut b) = UnixStream::pair().unwrap();
        for msg in &msgs {
            msg.write_to(&mut a).unwrap();
        }
        drop(a);
        for msg in &msgs {
            assert_eq!(NetMsg::read_from(&mut b).unwrap().as_ref(), Some(msg));
        }
        assert_eq!(NetMsg::read_from(&mut b).unwrap(), None);
    }

    #[test]
    fn rejects_unknown_tag() {
        let mut bytes = NetMsg::Read { at: at(0) }.encode();
        bytes[0] = 99;
        assert!(NetMsg::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut read = NetMsg::Read { at: at(0) }.encode();
        read.push(0);
        assert!(NetMsg::decode(&read).is_err());

        let mut write = NetMsg::Write {
            at: at(0),
            packet: packet(0),
        }
        .encode();
        write.pop();
        assert!(NetMsg::decode(&write).is_err());

        let mut short = NetMsg::Read { at: at(0) }.encode();
        short.pop();
        assert!(NetMsg::decode(&short).is_err());
        assert!(NetMsg::decode(&[]).is_err());
    }

    #[test]
    fn seeds_never_show_in_debug_output() {
        assert!(!format!("{:?}", at(0)).contains('9'));
    }

    #[test]
    fn rejects_oversized_frame_before_allocating() {
        let header = u32::MAX.to_be_bytes();
        assert!(read_frame(&mut &header[..], MAX_NET_FRAME).is_err());
    }

    #[test]
    fn rejects_truncated_frame() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &[1, 2, 3], MAX_NET_FRAME).unwrap();
        bytes.pop();
        assert!(read_frame(&mut &bytes[..], MAX_NET_FRAME).is_err());
        assert!(read_frame(&mut &bytes[..2], MAX_NET_FRAME).is_err());
    }

    #[test]
    fn read_cover_round_trips() {
        let at = BoxRef {
            stream: StreamSeed([7; SEED_LEN]),
            index: 3,
        };
        let msg = NetMsg::ReadCover { at };
        assert_eq!(NetMsg::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn status_bytes_reject_garbage() {
        assert!(
            NetStatus::from_bytes([9, 0, 0]).is_err(),
            "unknown status kind"
        );
        assert!(NetStatus::from_bytes([0, 99, 0]).is_err(), "unknown route");
        assert!(
            NetStatus::from_bytes([0, 0, 101]).is_err(),
            "percent over 100"
        );
    }

    #[test]
    fn use_direct_round_trips_and_takes_no_body() {
        assert_eq!(
            NetMsg::decode(&NetMsg::UseDirect.encode()).unwrap(),
            NetMsg::UseDirect
        );
        assert!(NetMsg::decode(&[TAG_USE_DIRECT, 0]).is_err());
    }
}
