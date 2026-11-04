//! Queues: one direction of a conversation, carried as an append-only stream of
//! write-once boxes.
//!
//! A queue secret yields two things by HKDF: the stream seed, which is all the transport
//! gets, and the key that seals every packet. The transport can't derive the key from the
//! seed, so whoever stores the boxes (or runs `purple-net`) sees only random bytes. Each
//! packet's AAD is its box index, so boxes can't be swapped or replayed at another
//! position undetected.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use purple_ipc::{PACKET_LEN, Packet, SEED_LEN, StreamSeed};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::{Error, Result};

const SECRET_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SALT: &[u8] = b"purple queue v2";

/// Bytes of plaintext one sealed packet carries.
pub const SEALED_LEN: usize = PACKET_LEN - NONCE_LEN - TAG_LEN;

/// Secret for one direction of a conversation, shared by both sides.
#[derive(Clone)]
pub struct QueueSecret(Zeroizing<[u8; SECRET_LEN]>);

impl std::fmt::Debug for QueueSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QueueSecret(..)")
    }
}

impl QueueSecret {
    /// A fresh secret from the OS RNG.
    ///
    /// # Errors
    /// Fails if the OS RNG fails.
    pub fn random() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        OsRng
            .try_fill_bytes(secret.as_mut_slice())
            .map_err(|_| Error::Malformed("OS random number generator failed"))?;
        Ok(Self(secret))
    }

    pub(crate) const fn from_bytes(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// A secret derived from other key material (an invite's bundle and intro queues).
    pub(crate) fn derive(ikm: &[u8], label: &[u8]) -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        expand(ikm, &[b"derive:", label], secret.as_mut_slice())?;
        Ok(Self(secret))
    }

    /// The stream seed and sealing key for this queue.
    ///
    /// # Errors
    /// Fails only if HKDF rejects the output length, which can't happen for these sizes.
    pub fn queue(&self) -> Result<Queue> {
        let mut seed = [0u8; SEED_LEN];
        expand(self.0.as_slice(), &[b"stream"], &mut seed)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        expand(self.0.as_slice(), &[b"key"], key.as_mut_slice())?;
        Ok(Queue {
            stream: StreamSeed(seed),
            key,
        })
    }
}

/// A queue's stream seed and the key that seals packets written to it.
pub struct Queue {
    stream: StreamSeed,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue").finish_non_exhaustive()
    }
}

impl Queue {
    /// The stream the transport writes this queue's boxes to.
    #[must_use]
    pub const fn stream(&self) -> StreamSeed {
        self.stream
    }

    /// Seal exactly [`SEALED_LEN`] bytes for box `index`.
    ///
    /// # Errors
    /// Fails if `plaintext` is the wrong length or the OS RNG fails.
    pub fn seal(&self, index: u64, plaintext: &[u8]) -> Result<Packet> {
        if plaintext.len() != SEALED_LEN {
            return Err(Error::Malformed("sealed plaintext has the wrong length"));
        }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Malformed("OS random number generator failed"))?;
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &index.to_be_bytes(),
                },
            )
            .map_err(|_| Error::Malformed("packet encryption failed"))?;
        Ok(Packet::from_slice(
            &[nonce.as_slice(), &ciphertext].concat(),
        )?)
    }

    /// Open the packet read from box `index`.
    ///
    /// # Errors
    /// Fails if the packet wasn't sealed with this queue's key for this index, or was altered.
    pub fn open(&self, index: u64, packet: &Packet) -> Result<Zeroizing<Vec<u8>>> {
        let (nonce, ciphertext) = packet
            .as_bytes()
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::Malformed("packet too short"))?;
        let plaintext = self
            .cipher()?
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: &index.to_be_bytes(),
                },
            )
            .map_err(|_| Error::Malformed("packet failed to decrypt"))?;
        Ok(Zeroizing::new(plaintext))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| Error::Malformed("invalid queue key"))
    }
}

fn expand(ikm: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<()> {
    Hkdf::<Sha256>::new(Some(SALT), ikm)
        .expand_multi_info(info, out)
        .map_err(|_| Error::Malformed("HKDF output length invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_stream_and_key() {
        let secret = QueueSecret::random().unwrap();
        let copy = QueueSecret::from_bytes(Zeroizing::new(*secret.as_bytes()));
        let (mine, theirs) = (secret.queue().unwrap(), copy.queue().unwrap());
        assert_eq!(mine.stream(), theirs.stream());
        let packet = mine.seal(3, &[7; SEALED_LEN]).unwrap();
        assert_eq!(theirs.open(3, &packet).unwrap().as_slice(), [7; SEALED_LEN]);
    }

    #[test]
    fn stream_seed_is_not_the_key() {
        let queue = QueueSecret::random().unwrap().queue().unwrap();
        assert_ne!(queue.stream().0, *queue.key);
        assert_ne!(queue.stream().0, [0; SEED_LEN]);
    }

    #[test]
    fn packets_open_only_at_their_own_index_with_their_own_key() {
        let queue = QueueSecret::random().unwrap().queue().unwrap();
        let packet = queue.seal(5, &[1; SEALED_LEN]).unwrap();
        assert!(queue.open(5, &packet).is_ok());
        assert!(queue.open(6, &packet).is_err());
        let other = QueueSecret::random().unwrap().queue().unwrap();
        assert!(other.open(5, &packet).is_err());

        let mut tampered = *packet.as_bytes();
        tampered[PACKET_LEN - 1] ^= 1;
        assert!(
            queue
                .open(5, &Packet::from_slice(&tampered).unwrap())
                .is_err()
        );
    }

    #[test]
    fn seal_rejects_wrong_length() {
        let queue = QueueSecret::random().unwrap().queue().unwrap();
        assert!(queue.seal(0, &[0; SEALED_LEN - 1]).is_err());
    }
}
