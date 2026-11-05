//! Messages between purple's processes, and the framing that carries them. Messages
//! between `purple-core` and `purple-net` are here; those with `purple-ui` are in [`ui`].
//!
//! Every message has a fixed layout and the decoder rejects anything else: unknown tags,
//! wrong lengths, oversized frames. Keep it that way, since `purple-core` parses these
//! straight from the process that faces the network.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

pub mod ui;

/// Size of every packet (one box). Must fit the transport's box payload: Namenlos boxes
/// hold 1549 bytes, and `purple-net` checks the daemon's geometry when it connects.
pub const PACKET_LEN: usize = 1536;
/// Size of a stream seed.
pub const SEED_LEN: usize = 32;

/// Fd where `purple-ui` finds its socket to `purple-core`.
pub const UI_CORE_FD: RawFd = 3;
/// Fd where `purple-core` finds its socket to `purple-ui`.
pub const CORE_UI_FD: RawFd = 3;
/// Fd where `purple-core` finds its socket to `purple-net`.
pub const CORE_NET_FD: RawFd = 4;
/// Fd where `purple-net` finds its socket to `purple-core`.
pub const NET_CORE_FD: RawFd = 3;

const MAX_NET_FRAME: usize = 1 + SEED_LEN + 8 + PACKET_LEN;

const TAG_WRITE: u8 = 1;
const TAG_READ: u8 = 2;
const TAG_FOUND: u8 = 3;
const TAG_EMPTY: u8 = 4;
const TAG_WRITTEN: u8 = 5;
const TAG_TAKEN: u8 = 6;

/// Identifies one append-only stream of boxes to the transport.
///
/// `purple-core` derives it one-way from a queue secret, so the transport can address boxes
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

/// One fixed-size packet. Its contents are opaque to everything but `purple-core`.
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

/// Messages between `purple-core` and `purple-net`.
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
}

impl NetMsg {
    /// Encode to the wire layout: tag, stream seed, index, then the packet if the message
    /// has one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, at, packet) = match self {
            Self::Write { at, packet } => (TAG_WRITE, at, Some(packet)),
            Self::Read { at } => (TAG_READ, at, None),
            Self::Found { at, packet } => (TAG_FOUND, at, Some(packet)),
            Self::Empty { at } => (TAG_EMPTY, at, None),
            Self::Written { at } => (TAG_WRITTEN, at, None),
            Self::Taken { at } => (TAG_TAKEN, at, None),
        };
        let mut out = Vec::with_capacity(MAX_NET_FRAME);
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
            TAG_READ | TAG_EMPTY | TAG_WRITTEN | TAG_TAKEN if !body.is_empty() => {
                Err(invalid("trailing bytes"))
            }
            TAG_READ => Ok(Self::Read { at }),
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
}
