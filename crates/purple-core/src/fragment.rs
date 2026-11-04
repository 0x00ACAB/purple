//! Splitting messages into fixed-size fragments and putting them back together. Each
//! fragment fills exactly one sealed packet (see [`crate::queue`]).
//!
//! Fragment layout: message ID (8 bytes), fragment index (u16 BE), fragment count (u16 BE),
//! data length (u16 BE), the data, then zeros to the end of the fragment. Every fragment but
//! the last is full, so each message has exactly one valid encoding.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;

use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::queue::SEALED_LEN;

const ID_LEN: usize = 8;
const HEADER_LEN: usize = ID_LEN + 2 + 2 + 2;

/// Data bytes that fit in one fragment.
pub const FRAGMENT_DATA_LEN: usize = SEALED_LEN - HEADER_LEN;
/// Most fragments one message may have, about 130 KB. Files will get their own chunking.
pub const MAX_FRAGMENTS: u16 = 64;
/// Most messages a [`Reassembler`] holds incomplete at once. With [`MAX_FRAGMENTS`] this
/// caps its memory at about 4 MB.
pub const MAX_IN_FLIGHT: usize = 32;

type MessageId = [u8; ID_LEN];

/// Split `message` into fragments of [`SEALED_LEN`] bytes under a fresh random message ID.
///
/// # Errors
/// Fails if `message` needs more than [`MAX_FRAGMENTS`] fragments, or if the OS RNG fails.
pub fn split(message: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut id = [0u8; ID_LEN];
    OsRng.try_fill_bytes(&mut id).map_err(io::Error::other)?;
    split_with_id(message, id)
}

fn split_with_id(message: &[u8], id: MessageId) -> io::Result<Vec<Vec<u8>>> {
    // An empty message is one fragment with no data.
    let chunks: Vec<&[u8]> = if message.is_empty() {
        vec![message]
    } else {
        message.chunks(FRAGMENT_DATA_LEN).collect()
    };
    let count = u16::try_from(chunks.len())
        .ok()
        .filter(|&count| count <= MAX_FRAGMENTS)
        .ok_or_else(|| invalid("message too large"))?;
    chunks
        .iter()
        .zip(0u16..)
        .map(|(chunk, index)| encode(id, index, count, chunk))
        .collect()
}

fn encode(id: MessageId, index: u16, count: u16, data: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(data.len()).map_err(|_| invalid("fragment too large"))?;
    let mut bytes = vec![0u8; SEALED_LEN];
    let (header, body) = bytes.split_at_mut(HEADER_LEN);
    header.copy_from_slice(
        &[
            id.as_slice(),
            &index.to_be_bytes(),
            &count.to_be_bytes(),
            &len.to_be_bytes(),
        ]
        .concat(),
    );
    body.get_mut(..data.len())
        .ok_or_else(|| invalid("fragment too large"))?
        .copy_from_slice(data);
    Ok(bytes)
}

struct Fragment<'a> {
    id: MessageId,
    index: u16,
    count: u16,
    data: &'a [u8],
}

fn decode(fragment: &[u8]) -> io::Result<Fragment<'_>> {
    if fragment.len() != SEALED_LEN {
        return Err(invalid("fragment has the wrong length"));
    }
    let short = || invalid("fragment too short");
    let (id, rest) = fragment.split_first_chunk::<ID_LEN>().ok_or_else(short)?;
    let (index, rest) = rest.split_first_chunk::<2>().ok_or_else(short)?;
    let (count, rest) = rest.split_first_chunk::<2>().ok_or_else(short)?;
    let (len, body) = rest.split_first_chunk::<2>().ok_or_else(short)?;
    let index = u16::from_be_bytes(*index);
    let count = u16::from_be_bytes(*count);
    let len = usize::from(u16::from_be_bytes(*len));

    if count == 0 || count > MAX_FRAGMENTS {
        return Err(invalid("fragment count out of range"));
    }
    if index >= count {
        return Err(invalid("fragment index out of range"));
    }
    let (data, padding) = body
        .split_at_checked(len)
        .ok_or_else(|| invalid("fragment length out of range"))?;
    if padding.iter().any(|&b| b != 0) {
        return Err(invalid("non-zero padding"));
    }
    let is_last = Some(index) == count.checked_sub(1);
    if !is_last && len != FRAGMENT_DATA_LEN {
        return Err(invalid("non-final fragment is not full"));
    }
    if is_last && len == 0 && count != 1 {
        return Err(invalid("empty final fragment"));
    }
    Ok(Fragment {
        id: *id,
        index,
        count,
        data,
    })
}

/// Puts fragments back together, in any order. Use one per contact queue, so a peer that
/// never finishes its messages can only block its own queue.
#[derive(Debug, Default)]
pub struct Reassembler {
    in_flight: HashMap<MessageId, Partial>,
}

#[derive(Debug)]
struct Partial {
    parts: Vec<Option<Vec<u8>>>,
    missing: usize,
}

impl Reassembler {
    /// Add one fragment. Returns the whole message once its last missing fragment arrives.
    /// Exact duplicates of a fragment already held are ignored.
    ///
    /// # Errors
    /// Fails on a malformed fragment, one that conflicts with fragments already held, or a
    /// new message when [`MAX_IN_FLIGHT`] messages are already incomplete.
    pub fn push(&mut self, fragment: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let fragment = decode(fragment)?;
        if fragment.count == 1 {
            return Ok(Some(fragment.data.to_vec()));
        }

        let full = self.in_flight.len() >= MAX_IN_FLIGHT;
        let partial = match self.in_flight.entry(fragment.id) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(_) if full => return Err(invalid("too many messages in flight")),
            Entry::Vacant(entry) => {
                let count = usize::from(fragment.count);
                entry.insert(Partial {
                    parts: vec![None; count],
                    missing: count,
                })
            }
        };
        if partial.parts.len() != usize::from(fragment.count) {
            return Err(invalid("fragment count changed"));
        }
        let slot = partial
            .parts
            .get_mut(usize::from(fragment.index))
            .ok_or_else(|| invalid("fragment index out of range"))?;
        match slot {
            Some(held) if held == fragment.data => return Ok(None),
            Some(_) => return Err(invalid("conflicting fragment")),
            None => {
                *slot = Some(fragment.data.to_vec());
                partial.missing = partial.missing.saturating_sub(1);
            }
        }
        if partial.missing > 0 {
            return Ok(None);
        }

        let done = self
            .in_flight
            .remove(&fragment.id)
            .ok_or_else(|| invalid("completed message vanished"))?;
        Ok(Some(done.parts.into_iter().flatten().flatten().collect()))
    }
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: usize = FRAGMENT_DATA_LEN;

    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn reassemble(packets: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut r = Reassembler::default();
        let mut out = None;
        for packet in packets {
            if let Some(done) = r.push(packet).unwrap() {
                assert!(out.is_none(), "message completed twice");
                out = Some(done);
            }
        }
        out
    }

    #[test]
    fn round_trips_at_every_boundary() {
        let max = N * usize::from(MAX_FRAGMENTS);
        for len in [0, 1, N - 1, N, N + 1, 3 * N + 5, max] {
            let msg = message(len);
            let packets = split(&msg).unwrap();
            assert_eq!(packets.len(), len.div_ceil(N).max(1), "len {len}");
            assert_eq!(reassemble(&packets).unwrap(), msg, "len {len}");
        }
        assert!(split(&message(max + 1)).is_err());
    }

    #[test]
    fn handles_reordering_duplicates_and_interleaving() {
        let a = message(3 * N + 1);
        let b = message(2 * N + 7);
        let pa = split(&a).unwrap();
        let pb = split(&b).unwrap();
        let mut r = Reassembler::default();
        assert_eq!(r.push(&pa[3]).unwrap(), None);
        assert_eq!(r.push(&pb[1]).unwrap(), None);
        assert_eq!(r.push(&pa[0]).unwrap(), None);
        assert_eq!(r.push(&pa[0]).unwrap(), None);
        assert_eq!(r.push(&pb[2]).unwrap(), None);
        assert_eq!(r.push(&pa[2]).unwrap(), None);
        assert_eq!(r.push(&pb[0]).unwrap(), Some(b));
        assert_eq!(r.push(&pa[1]).unwrap(), Some(a));
        assert!(r.in_flight.is_empty());
    }

    #[test]
    fn rejects_conflicting_fragments() {
        let id = [7; ID_LEN];
        let mut r = Reassembler::default();
        r.push(&encode(id, 0, 2, &[1; N]).unwrap()).unwrap();
        assert!(r.push(&encode(id, 0, 2, &[2; N]).unwrap()).is_err());
        assert!(r.push(&encode(id, 1, 3, &[1; N]).unwrap()).is_err());
    }

    #[test]
    fn rejects_non_canonical_fragments() {
        let id = [1; ID_LEN];
        let mut r = Reassembler::default();
        // Short fragment that isn't the last.
        assert!(r.push(&encode(id, 0, 2, &[1; 10]).unwrap()).is_err());
        // Empty last fragment of a multi-fragment message.
        assert!(r.push(&encode(id, 1, 2, &[]).unwrap()).is_err());
        // Index and count out of range.
        assert!(r.push(&encode(id, 2, 2, &[1; 10]).unwrap()).is_err());
        assert!(r.push(&encode(id, 0, 0, &[]).unwrap()).is_err());
        assert!(
            r.push(&encode(id, 0, MAX_FRAGMENTS + 1, &[1; N]).unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_bad_length_and_dirty_padding() {
        let mut bad_len = encode([0; ID_LEN], 0, 1, b"hi").unwrap();
        bad_len[HEADER_LEN - 2..HEADER_LEN].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode(&bad_len).is_err());

        let mut dirty = encode([0; ID_LEN], 0, 1, b"hi").unwrap();
        dirty[SEALED_LEN - 1] = 1;
        assert!(decode(&dirty).is_err());

        assert!(decode(&[0; SEALED_LEN - 1]).is_err());
    }

    #[test]
    fn limits_messages_in_flight() {
        let mut r = Reassembler::default();
        for i in 0..MAX_IN_FLIGHT {
            let id = [u8::try_from(i).unwrap(); ID_LEN];
            r.push(&encode(id, 0, 2, &[0; N]).unwrap()).unwrap();
        }
        assert!(
            r.push(&encode([0xFF; ID_LEN], 0, 2, &[0; N]).unwrap())
                .is_err()
        );
        // Messages already in flight can still finish.
        assert!(
            r.push(&encode([0; ID_LEN], 1, 2, &[1]).unwrap())
                .unwrap()
                .is_some()
        );
    }
}
