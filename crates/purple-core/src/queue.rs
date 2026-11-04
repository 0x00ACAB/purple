//! Queues: the mailboxes one direction of a conversation uses over time, and the sealing
//! of each packet so the provider storing it sees only random bytes.
//!
//! A queue secret yields a different mailbox and key for every epoch (one UTC day). The
//! provider can't link one day's mailbox to the next, and can't read fragment headers or
//! the libsignal metadata inside.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use purple_ipc::{MAILBOX_ID_LEN, MailboxId, PACKET_LEN, Packet};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::{Error, Result};

const SECRET_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SALT: &[u8] = b"purple queue v1";

/// Bytes of plaintext one sealed packet carries.
pub const SEALED_LEN: usize = PACKET_LEN - NONCE_LEN - TAG_LEN;
/// Length of one epoch. Each epoch uses a fresh mailbox and key.
pub const EPOCH_SECS: u64 = 86_400;

/// The epoch that `unix_secs` falls in.
#[must_use]
pub const fn epoch(unix_secs: u64) -> u64 {
    match unix_secs.checked_div(EPOCH_SECS) {
        Some(epoch) => epoch,
        None => 0,
    }
}

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

    /// A secret derived from other key material, for queues that don't rotate (an invite's
    /// bundle and intro queues).
    pub(crate) fn derive(ikm: &[u8], label: &[u8]) -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        expand(ikm, &[b"derive:", label], secret.as_mut_slice())?;
        Ok(Self(secret))
    }

    /// The mailbox and key for `epoch`.
    ///
    /// # Errors
    /// Fails only if HKDF rejects the output length, which can't happen for these sizes.
    pub fn queue(&self, epoch: u64) -> Result<Queue> {
        let epoch = epoch.to_be_bytes();
        let mut mailbox = [0u8; MAILBOX_ID_LEN];
        expand(self.0.as_slice(), &[b"mailbox:", &epoch], &mut mailbox)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        expand(self.0.as_slice(), &[b"key:", &epoch], key.as_mut_slice())?;
        Ok(Queue {
            mailbox: MailboxId(mailbox),
            key,
        })
    }
}

/// One mailbox and the key that seals packets sent to it.
pub struct Queue {
    mailbox: MailboxId,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue")
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}

impl Queue {
    /// The mailbox this queue delivers to.
    #[must_use]
    pub const fn mailbox(&self) -> MailboxId {
        self.mailbox
    }

    /// Seal exactly [`SEALED_LEN`] bytes into one packet.
    ///
    /// # Errors
    /// Fails if `plaintext` is the wrong length or the OS RNG fails.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Packet> {
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
                    aad: &self.mailbox.0,
                },
            )
            .map_err(|_| Error::Malformed("packet encryption failed"))?;
        Ok(Packet::from_slice(
            &[nonce.as_slice(), &ciphertext].concat(),
        )?)
    }

    /// Open a packet sealed for this queue.
    ///
    /// # Errors
    /// Fails if the packet wasn't sealed with this queue's key and mailbox, or was altered.
    pub fn open(&self, packet: &Packet) -> Result<Zeroizing<Vec<u8>>> {
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
                    aad: &self.mailbox.0,
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
    fn mailbox_and_key_change_every_epoch() {
        let secret = QueueSecret::random().unwrap();
        let today = secret.queue(20_000).unwrap();
        let tomorrow = secret.queue(20_001).unwrap();
        assert_ne!(today.mailbox(), tomorrow.mailbox());
        assert_ne!(*today.key, *tomorrow.key);
        // Both sides derive the same queue from the same secret.
        assert_eq!(
            QueueSecret::from_bytes(Zeroizing::new(*secret.as_bytes()))
                .queue(20_000)
                .unwrap()
                .mailbox(),
            today.mailbox()
        );
    }

    #[test]
    fn sealed_packet_opens_only_with_its_own_queue() {
        let secret = QueueSecret::random().unwrap();
        let queue = secret.queue(1).unwrap();
        let plaintext = vec![7u8; SEALED_LEN];
        let packet = queue.seal(&plaintext).unwrap();
        assert_eq!(queue.open(&packet).unwrap().as_slice(), plaintext);

        assert!(secret.queue(2).unwrap().open(&packet).is_err());
        assert!(
            QueueSecret::random()
                .unwrap()
                .queue(1)
                .unwrap()
                .open(&packet)
                .is_err()
        );

        let mut tampered = *packet.as_bytes();
        tampered[PACKET_LEN - 1] ^= 1;
        assert!(queue.open(&Packet::from_slice(&tampered).unwrap()).is_err());
    }

    #[test]
    fn seal_rejects_wrong_length() {
        let queue = QueueSecret::random().unwrap().queue(0).unwrap();
        assert!(queue.seal(&[0; SEALED_LEN - 1]).is_err());
    }

    #[test]
    fn epochs_are_utc_days() {
        assert_eq!(epoch(0), 0);
        assert_eq!(epoch(EPOCH_SECS - 1), 0);
        assert_eq!(epoch(EPOCH_SECS), 1);
    }
}
