//! purple-core library: sessions and packet padding.
//!
//! Padding of message payloads into fixed-size packets.
//!
//! Until libsignal lands (build step 2), packets carry padded plaintext. After that, the
//! padded plaintext is encrypted and the ciphertext fills the packet.

pub mod session;

use std::io;

use purple_ipc::{PACKET_LEN, Packet};

const LEN_PREFIX: usize = 2;

/// Largest payload that fits in one packet.
pub const MAX_PAYLOAD: usize = PACKET_LEN - LEN_PREFIX;

/// Pad `payload` to exactly one packet: a 2-byte big-endian length, the payload, then zeros.
///
/// # Errors
/// Fails if `payload` is longer than [`MAX_PAYLOAD`].
pub fn pad(payload: &[u8]) -> io::Result<Packet> {
    let len = u16::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_PAYLOAD)
        .ok_or_else(|| invalid("payload does not fit in one packet"))?;
    let mut bytes = [0u8; PACKET_LEN];
    let (prefix, rest) = bytes.split_at_mut(LEN_PREFIX);
    prefix.copy_from_slice(&len.to_be_bytes());
    rest.get_mut(..payload.len())
        .ok_or_else(|| invalid("payload does not fit in one packet"))?
        .copy_from_slice(payload);
    Packet::from_slice(&bytes)
}

/// Recover the payload from a padded packet.
///
/// # Errors
/// Fails if the length prefix is out of range or the padding is not all zeros.
pub fn unpad(packet: &Packet) -> io::Result<&[u8]> {
    let (prefix, rest) = packet
        .as_bytes()
        .split_first_chunk::<LEN_PREFIX>()
        .ok_or_else(|| invalid("packet too short"))?;
    let len = usize::from(u16::from_be_bytes(*prefix));
    if len > MAX_PAYLOAD {
        return Err(invalid("length prefix out of range"));
    }
    let (payload, padding) = rest.split_at(len);
    if padding.iter().any(|&b| b != 0) {
        return Err(invalid("non-zero padding"));
    }
    Ok(payload)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_empty_short_and_max_payloads() {
        for payload in [&[][..], b"hello", &[0xAB; MAX_PAYLOAD]] {
            assert_eq!(unpad(&pad(payload).unwrap()).unwrap(), payload);
        }
    }

    #[test]
    fn rejects_oversized_payload() {
        assert!(pad(&[0; MAX_PAYLOAD + 1]).is_err());
    }

    #[test]
    fn rejects_bad_prefix_and_dirty_padding() {
        let mut bad_prefix = [0u8; PACKET_LEN];
        bad_prefix[0] = 0xFF;
        assert!(unpad(&Packet::from_slice(&bad_prefix).unwrap()).is_err());

        let mut dirty_padding = [0u8; PACKET_LEN];
        dirty_padding[PACKET_LEN - 1] = 1;
        assert!(unpad(&Packet::from_slice(&dirty_padding).unwrap()).is_err());
    }
}
