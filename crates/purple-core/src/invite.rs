//! Invites: the small payload in a QR code or link.
//!
//! An invite holds Bob's identity key and a fresh 32-byte key. Two queues derive from that
//! key: the bundle queue, where Bob stores his prekey bundle, and the intro queue, where
//! Alice sends her first message. Alice fetches the bundle through the mixnet. libsignal
//! then checks the bundle's signatures against the identity key from the invite, so
//! whoever stores the bundle (or saw the QR code) can't swap in their own keys.

use std::fmt;

use libsignal_protocol::kem;
use libsignal_protocol::{
    IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, PublicKey, SignalProtocolError,
    SignedPreKeyId,
};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::queue::{Queue, QueueSecret};
use crate::session::{Error, REGISTRATION_ID, Result, device_id};

const VERSION: u8 = 1;
const IDENTITY_LEN: usize = 33;
const KEY_LEN: usize = 32;

/// Length of an encoded invite.
pub const INVITE_LEN: usize = 1 + IDENTITY_LEN + KEY_LEN;

/// What goes in the QR code or link.
#[derive(Clone)]
pub struct Invite {
    identity: IdentityKey,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite").finish_non_exhaustive()
    }
}

impl Invite {
    /// A new invite for `identity` with a fresh key.
    pub(crate) fn create(identity: IdentityKey) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng
            .try_fill_bytes(key.as_mut_slice())
            .map_err(|_| Error::Malformed("OS random number generator failed"))?;
        Ok(Self { identity, key })
    }

    /// Encode for a QR code or link: version, identity key, invite key.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(INVITE_LEN));
        out.push(VERSION);
        out.extend_from_slice(&self.identity.serialize());
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
        let key = Zeroizing::new(r.take::<KEY_LEN>()?);
        r.finish()?;
        Ok(Self { identity, key })
    }

    /// Queue where the inviter stores the prekey bundle.
    pub(crate) fn bundle_queue(&self) -> Result<Queue> {
        QueueSecret::derive(self.key.as_slice(), b"bundle")?.queue(0)
    }

    /// Queue where the accepter sends the first message.
    pub(crate) fn intro_queue(&self) -> Result<Queue> {
        QueueSecret::derive(self.key.as_slice(), b"intro")?.queue(0)
    }

    /// Rebuild a fetched bundle under this invite's identity key. Its signatures are
    /// checked against that key when the session starts.
    pub(crate) fn decode_bundle(&self, bytes: &[u8]) -> Result<PreKeyBundle> {
        let mut r = Reader(bytes);
        let pre_key_id = PreKeyId::from(r.u32()?);
        let pre_key = curve_key(r.bytes()?)?;
        let signed_id = SignedPreKeyId::from(r.u32()?);
        let signed_key = curve_key(r.bytes()?)?;
        let signed_signature = r.bytes()?.to_vec();
        let kyber_id = KyberPreKeyId::from(r.u32()?);
        let kyber_key = kem::PublicKey::deserialize(r.bytes()?)?;
        let kyber_signature = r.bytes()?.to_vec();
        r.finish()?;

        Ok(PreKeyBundle::new(
            REGISTRATION_ID,
            device_id()?,
            Some((pre_key_id, pre_key)),
            signed_id,
            signed_key,
            signed_signature,
            kyber_id,
            kyber_key,
            kyber_signature,
            self.identity,
        )?)
    }
}

/// Bundle layout: one-time, signed and Kyber prekeys, each as a u32 ID followed by
/// u16-length-prefixed key (and signature) bytes. The identity key comes from the invite.
pub(crate) fn encode_bundle(bundle: &PreKeyBundle) -> Result<Vec<u8>> {
    let (pre_key_id, pre_key) = bundle
        .pre_key_id()?
        .zip(bundle.pre_key_public()?)
        .ok_or(Error::Malformed("bundle has no one-time prekey"))?;
    let mut out = Vec::new();
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

fn curve_key(bytes: &[u8]) -> Result<PublicKey> {
    Ok(PublicKey::deserialize(bytes).map_err(SignalProtocolError::from)?)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::Malformed("bundle field too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
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

    #[test]
    fn invite_fits_a_small_qr_code() {
        let (invite, _) = Account::generate().unwrap().create_invite().unwrap();
        assert_eq!(invite.encode().len(), INVITE_LEN);
        assert_eq!(INVITE_LEN, 66);
    }

    #[test]
    fn accepted_invite_starts_a_session() {
        let mut bob = Account::generate().unwrap();
        let (invite, bundle) = bob.create_invite().unwrap();
        let scanned = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(
            scanned.bundle_queue().unwrap().mailbox(),
            invite.bundle_queue().unwrap().mailbox()
        );

        let mut alice = Account::generate().unwrap();
        alice.accept_invite("bob", &scanned, &bundle).unwrap();
        let hello = alice.encrypt("bob", b"hello").unwrap();
        assert_eq!(bob.decrypt("alice", &hello).unwrap(), b"hello");
    }

    #[test]
    fn bundle_and_intro_queues_differ() {
        let (invite, _) = Account::generate().unwrap().create_invite().unwrap();
        assert_ne!(
            invite.bundle_queue().unwrap().mailbox(),
            invite.intro_queue().unwrap().mailbox()
        );
    }

    #[test]
    fn rejects_malformed_invites() {
        let (invite, _) = Account::generate().unwrap().create_invite().unwrap();
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
    fn rejects_truncated_or_padded_bundles() {
        let (invite, bundle) = Account::generate().unwrap().create_invite().unwrap();
        assert!(invite.decode_bundle(&bundle[..bundle.len() - 1]).is_err());
        let mut padded = bundle;
        padded.push(0);
        assert!(invite.decode_bundle(&padded).is_err());
    }

    #[test]
    fn substituted_bundle_fails_identity_check() {
        // Someone who saw Bob's QR code can store their own prekeys in his bundle queue.
        // Their signatures don't match Bob's identity, so Alice refuses.
        let (invite, _) = Account::generate().unwrap().create_invite().unwrap();
        let (_, mallory_bundle) = Account::generate().unwrap().create_invite().unwrap();
        let mut alice = Account::generate().unwrap();
        assert!(
            alice
                .accept_invite("bob", &invite, &mallory_bundle)
                .is_err()
        );
    }
}
