//! Invites: the small payload in a QR code or link, and the encrypted prekey bundle it
//! points to.
//!
//! An invite holds Bob's identity key, the mailbox where his encrypted bundle waits, and
//! the key that decrypts it. Alice fetches the bundle through the mixnet. libsignal then
//! checks the bundle's signatures against the identity key from the invite, so whoever
//! stores the bundle can't swap in their own keys.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use libsignal_protocol::kem;
use libsignal_protocol::{
    IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, PublicKey, SignalProtocolError,
    SignedPreKeyId,
};
use purple_ipc::{MAILBOX_ID_LEN, MailboxId};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::session::{Error, REGISTRATION_ID, Result, device_id};

const VERSION: u8 = 1;
const IDENTITY_LEN: usize = 33;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Length of an encoded invite.
pub const INVITE_LEN: usize = 1 + IDENTITY_LEN + MAILBOX_ID_LEN + KEY_LEN;

/// What goes in the QR code or link.
pub struct Invite {
    identity: IdentityKey,
    bundle_mailbox: MailboxId,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite")
            .field("bundle_mailbox", &self.bundle_mailbox)
            .finish_non_exhaustive()
    }
}

impl Invite {
    /// Mailbox where the encrypted bundle waits.
    #[must_use]
    pub const fn bundle_mailbox(&self) -> MailboxId {
        self.bundle_mailbox
    }

    /// Encode for a QR code or link: version, identity key, bundle mailbox, bundle key.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(INVITE_LEN));
        out.push(VERSION);
        out.extend_from_slice(&self.identity.serialize());
        out.extend_from_slice(&self.bundle_mailbox.0);
        out.extend_from_slice(self.key.as_slice());
        out
    }

    /// Decode an invite.
    ///
    /// # Errors
    /// Fails on the wrong length, an unknown version, or an invalid identity key.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != INVITE_LEN {
            return Err(Error::Malformed("invite has the wrong length"));
        }
        let mut r = Reader(bytes);
        if r.take::<1>()? != [VERSION] {
            return Err(Error::Malformed("unknown invite version"));
        }
        let identity = IdentityKey::decode(&r.take::<IDENTITY_LEN>()?)?;
        let bundle_mailbox = MailboxId(r.take::<MAILBOX_ID_LEN>()?);
        let key = Zeroizing::new(r.take::<KEY_LEN>()?);
        r.finish()?;
        Ok(Self {
            identity,
            bundle_mailbox,
            key,
        })
    }

    /// Create an invite for `identity` with a fresh key, and seal `bundle` under it.
    /// Returns the invite and the encrypted bundle to store at `bundle_mailbox`.
    pub(crate) fn create(
        identity: IdentityKey,
        bundle_mailbox: MailboxId,
        first_mailbox: MailboxId,
        bundle: &PreKeyBundle,
    ) -> Result<(Self, Vec<u8>)> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(key.as_mut_slice())?;
        let invite = Self {
            identity,
            bundle_mailbox,
            key,
        };
        let sealed = invite.seal(first_mailbox, bundle)?;
        Ok((invite, sealed))
    }

    /// Encrypt `bundle` and the mailbox for the first message under this invite's key.
    fn seal(&self, first_mailbox: MailboxId, bundle: &PreKeyBundle) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let plaintext = encode_bundle(first_mailbox, bundle)?;
        let aad = self.aad();
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Malformed("bundle encryption failed"))?;
        Ok([nonce.as_slice(), &ciphertext].concat())
    }

    /// Decrypt a sealed bundle. Returns it with this invite's identity key, plus the mailbox
    /// for the first message. The bundle's signatures are checked when a session starts.
    pub(crate) fn open(&self, sealed: &[u8]) -> Result<(PreKeyBundle, MailboxId)> {
        let (nonce, ciphertext) = sealed
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::Malformed("sealed bundle too short"))?;
        let aad = self.aad();
        let plaintext = self
            .cipher()?
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Malformed("sealed bundle failed to decrypt"))?;
        decode_bundle(self.identity, &plaintext)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| Error::Malformed("invalid bundle key"))
    }

    /// Binds the sealed bundle to this invite's version, identity and mailbox.
    fn aad(&self) -> Vec<u8> {
        [
            &[VERSION][..],
            &self.identity.serialize(),
            &self.bundle_mailbox.0,
        ]
        .concat()
    }
}

/// Bundle layout: first mailbox, then one-time, signed and Kyber prekeys, each as a u32 ID
/// followed by u16-length-prefixed key (and signature) bytes.
fn encode_bundle(first_mailbox: MailboxId, bundle: &PreKeyBundle) -> Result<Vec<u8>> {
    let (pre_key_id, pre_key) = bundle
        .pre_key_id()?
        .zip(bundle.pre_key_public()?)
        .ok_or(Error::Malformed("bundle has no one-time prekey"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&first_mailbox.0);
    out.extend_from_slice(&u32::from(pre_key_id).to_be_bytes());
    put_bytes(&mut out, &pre_key.serialize())?;
    out.extend_from_slice(&u32::from(bundle.signed_pre_key_id()?).to_be_bytes());
    put_bytes(&mut out, &bundle.signed_pre_key_public()?.serialize())?;
    put_bytes(&mut out, bundle.signed_pre_key_signature()?)?;
    out.extend_from_slice(&u32::from(bundle.kyber_pre_key_id()?).to_be_bytes());
    put_bytes(&mut out, &bundle.kyber_pre_key_public()?.serialize())?;
    put_bytes(&mut out, bundle.kyber_pre_key_signature()?)?;
    Ok(out)
}

fn decode_bundle(identity: IdentityKey, bytes: &[u8]) -> Result<(PreKeyBundle, MailboxId)> {
    let mut r = Reader(bytes);
    let first_mailbox = MailboxId(r.take::<MAILBOX_ID_LEN>()?);
    let pre_key_id = PreKeyId::from(r.u32()?);
    let pre_key = curve_key(r.bytes()?)?;
    let signed_id = SignedPreKeyId::from(r.u32()?);
    let signed_key = curve_key(r.bytes()?)?;
    let signed_signature = r.bytes()?.to_vec();
    let kyber_id = KyberPreKeyId::from(r.u32()?);
    let kyber_key = kem::PublicKey::deserialize(r.bytes()?)?;
    let kyber_signature = r.bytes()?.to_vec();
    r.finish()?;

    let bundle = PreKeyBundle::new(
        REGISTRATION_ID,
        device_id()?,
        Some((pre_key_id, pre_key)),
        signed_id,
        signed_key,
        signed_signature,
        kyber_id,
        kyber_key,
        kyber_signature,
        identity,
    )?;
    Ok((bundle, first_mailbox))
}

fn curve_key(bytes: &[u8]) -> Result<PublicKey> {
    Ok(PublicKey::deserialize(bytes).map_err(SignalProtocolError::from)?)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::Malformed("bundle field too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(out)
        .map_err(|_| Error::Malformed("OS random number generator failed"))
}

/// Reads fields front to back and rejects truncated or trailing bytes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Malformed("truncated"))?;
        self.0 = rest;
        Ok(*head)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(u16::from_be_bytes(self.take::<2>()?));
        let (head, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(Error::Malformed("truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    const fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Account;

    const BUNDLE_BOX: MailboxId = MailboxId([1; MAILBOX_ID_LEN]);
    const FIRST_BOX: MailboxId = MailboxId([2; MAILBOX_ID_LEN]);

    #[test]
    fn invite_fits_a_small_qr_code() {
        let mut bob = Account::generate().unwrap();
        let (invite, _) = bob.create_invite(BUNDLE_BOX, FIRST_BOX).unwrap();
        assert_eq!(invite.encode().len(), INVITE_LEN);
        assert_eq!(INVITE_LEN, 98);
    }

    #[test]
    fn accepted_invite_starts_a_session() {
        let mut bob = Account::generate().unwrap();
        let (invite, sealed) = bob.create_invite(BUNDLE_BOX, FIRST_BOX).unwrap();

        let scanned = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(scanned.bundle_mailbox(), BUNDLE_BOX);
        let mut alice = Account::generate().unwrap();
        let first = alice.accept_invite("bob", &scanned, &sealed).unwrap();
        assert_eq!(first, FIRST_BOX);

        let hello = alice.encrypt("bob", b"hello").unwrap();
        assert_eq!(bob.decrypt("alice", &hello).unwrap(), b"hello");
    }

    #[test]
    fn rejects_malformed_invites() {
        let mut bob = Account::generate().unwrap();
        let (invite, _) = bob.create_invite(BUNDLE_BOX, FIRST_BOX).unwrap();
        let good = invite.encode();

        assert!(Invite::decode(&good[..INVITE_LEN - 1]).is_err());
        let mut wrong_version = good.to_vec();
        wrong_version[0] = 2;
        assert!(Invite::decode(&wrong_version).is_err());
        let mut bad_identity = good.to_vec();
        bad_identity[1] = 0xFF;
        assert!(Invite::decode(&bad_identity).is_err());
    }

    #[test]
    fn tampered_or_mismatched_bundle_is_rejected() {
        let mut bob = Account::generate().unwrap();
        let (invite, sealed) = bob.create_invite(BUNDLE_BOX, FIRST_BOX).unwrap();

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            Account::generate()
                .unwrap()
                .accept_invite("bob", &invite, &tampered)
                .is_err()
        );

        // Same bundle presented under another invite's key and mailbox.
        let (other, _) = bob
            .create_invite(MailboxId([9; MAILBOX_ID_LEN]), FIRST_BOX)
            .unwrap();
        assert!(
            Account::generate()
                .unwrap()
                .accept_invite("bob", &other, &sealed)
                .is_err()
        );
    }

    #[test]
    fn substituted_bundle_fails_identity_check() {
        // Someone who saw Bob's QR code knows the bundle key, so they can seal their own
        // prekeys under it. The signatures don't match Bob's identity, so Alice refuses.
        let mut bob = Account::generate().unwrap();
        let (invite, _) = bob.create_invite(BUNDLE_BOX, FIRST_BOX).unwrap();
        let mut mallory = Account::generate().unwrap();
        let forged = invite
            .seal(FIRST_BOX, &mallory.new_prekey_bundle().unwrap())
            .unwrap();
        assert!(
            Account::generate()
                .unwrap()
                .accept_invite("bob", &invite, &forged)
                .is_err()
        );
    }
}
