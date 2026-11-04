//! Messages between purple's processes, and the framing that carries them.
//!
//! Every message has a fixed layout and the decoder rejects anything else: unknown tags,
//! wrong lengths, oversized frames. Keep it that way, since `purple-core` parses these
//! straight from the process that faces the network.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Size of every packet on the wire. Placeholder until the Nym packet size is wired in.
pub const PACKET_LEN: usize = 2048;
/// Size of a mailbox address.
pub const MAILBOX_ID_LEN: usize = 32;

/// Fd where `purple-ui` finds its socket to `purple-core`.
pub const UI_CORE_FD: RawFd = 3;
/// Fd where `purple-core` finds its socket to `purple-ui`.
pub const CORE_UI_FD: RawFd = 3;
/// Fd where `purple-core` finds its socket to `purple-net`.
pub const CORE_NET_FD: RawFd = 4;
/// Fd where `purple-net` finds its socket to `purple-core`.
pub const NET_CORE_FD: RawFd = 3;

const MAX_FRAME: usize = 1 + MAILBOX_ID_LEN + PACKET_LEN;

const TAG_SEND: u8 = 1;
const TAG_FETCH: u8 = 2;
const TAG_DELIVERED: u8 = 3;
const TAG_FETCH_DONE: u8 = 4;

/// Address of a mailbox queue at a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MailboxId(pub [u8; MAILBOX_ID_LEN]);

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
    /// core to net: queue `packet` for delivery to `mailbox`.
    Send {
        /// Destination mailbox.
        mailbox: MailboxId,
        /// Packet to deliver.
        packet: Packet,
    },
    /// core to net: fetch everything waiting in `mailbox`.
    Fetch {
        /// Mailbox to drain.
        mailbox: MailboxId,
    },
    /// net to core: one packet from a fetched mailbox.
    Delivered {
        /// Mailbox the packet came from.
        mailbox: MailboxId,
        /// The packet.
        packet: Packet,
    },
    /// net to core: no more packets for this fetch.
    FetchDone {
        /// Mailbox the fetch was for.
        mailbox: MailboxId,
    },
}

impl NetMsg {
    /// Encode to the wire layout: tag, mailbox, then the packet if the message has one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (tag, mailbox, packet) = match self {
            Self::Send { mailbox, packet } => (TAG_SEND, mailbox, Some(packet)),
            Self::Fetch { mailbox } => (TAG_FETCH, mailbox, None),
            Self::Delivered { mailbox, packet } => (TAG_DELIVERED, mailbox, Some(packet)),
            Self::FetchDone { mailbox } => (TAG_FETCH_DONE, mailbox, None),
        };
        let mut out = Vec::with_capacity(MAX_FRAME);
        out.push(tag);
        out.extend_from_slice(&mailbox.0);
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
        let (id, body) = rest
            .split_first_chunk::<MAILBOX_ID_LEN>()
            .ok_or_else(|| invalid("message too short"))?;
        let mailbox = MailboxId(*id);
        match tag {
            TAG_SEND => Ok(Self::Send {
                mailbox,
                packet: Packet::from_slice(body)?,
            }),
            TAG_DELIVERED => Ok(Self::Delivered {
                mailbox,
                packet: Packet::from_slice(body)?,
            }),
            TAG_FETCH | TAG_FETCH_DONE if !body.is_empty() => Err(invalid("trailing bytes")),
            TAG_FETCH => Ok(Self::Fetch { mailbox }),
            TAG_FETCH_DONE => Ok(Self::FetchDone { mailbox }),
            _ => Err(invalid("unknown message tag")),
        }
    }

    /// Write this message as one frame.
    ///
    /// # Errors
    /// Fails if the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        write_frame(w, &self.encode())
    }

    /// Read one message. Returns `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error, a truncated or oversized frame, or an invalid message.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        read_frame(r)?.map(|frame| Self::decode(&frame)).transpose()
    }
}

/// Write `body` with a 4-byte big-endian length prefix.
///
/// # Errors
/// Fails if `body` is larger than the biggest message, or if the write fails.
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME {
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
/// Fails on a read error, a truncated frame, or a length over the biggest message.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
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
    if len > MAX_FRAME {
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

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    #[test]
    fn every_message_round_trips_over_a_socket() {
        let mailbox = MailboxId([9; MAILBOX_ID_LEN]);
        let msgs = [
            NetMsg::Send {
                mailbox,
                packet: packet(1),
            },
            NetMsg::Fetch { mailbox },
            NetMsg::Delivered {
                mailbox,
                packet: packet(2),
            },
            NetMsg::FetchDone { mailbox },
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
        let mut bytes = NetMsg::Fetch {
            mailbox: MailboxId([0; MAILBOX_ID_LEN]),
        }
        .encode();
        bytes[0] = 99;
        assert!(NetMsg::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mailbox = MailboxId([0; MAILBOX_ID_LEN]);
        let mut fetch = NetMsg::Fetch { mailbox }.encode();
        fetch.push(0);
        assert!(NetMsg::decode(&fetch).is_err());

        let mut send = NetMsg::Send {
            mailbox,
            packet: packet(0),
        }
        .encode();
        send.pop();
        assert!(NetMsg::decode(&send).is_err());

        assert!(NetMsg::decode(&[TAG_FETCH, 0, 0]).is_err());
        assert!(NetMsg::decode(&[]).is_err());
    }

    #[test]
    fn rejects_oversized_frame_before_allocating() {
        let header = u32::MAX.to_be_bytes();
        assert!(read_frame(&mut &header[..]).is_err());
    }

    #[test]
    fn rejects_truncated_frame() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &[1, 2, 3]).unwrap();
        bytes.pop();
        assert!(read_frame(&mut &bytes[..]).is_err());
        assert!(read_frame(&mut &bytes[..2]).is_err());
    }
}
