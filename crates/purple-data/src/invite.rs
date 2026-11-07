//! Invites: the small payload in a QR code or link.
//!
//! An invite holds Bob's identity key and a fresh 32-byte key. Two queues derive from that
//! key: the bundle queue, where Bob stores his prekey bundle, and the intro queue, where
//! Alice sends her first message. Alice fetches the bundle through the mixnet. libsignal
//! then checks the bundle's signatures against the identity key from the invite, so
//! whoever stores the bundle (or saw the QR code) can't swap in their own keys.
//!
//! Since version 2 an invite also names the store its boxes live on, so an invite made on
//! one store isn't accepted on another, where its bundle would never be found.

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

const VERSION: u8 = 2;
/// Invites from before they named their store. Only read back from the vault.
const OLD_VERSION: u8 = 1;
const IDENTITY_LEN: usize = 33;
const KEY_LEN: usize = 32;
/// Longest onion host an invite carries: 56 base32 characters and ".onion".
const MAX_HOST_LEN: usize = 62;

const STORE_MEMORY: u8 = 0;
const STORE_DEV: u8 = 1;
const STORE_NAMENLOS: u8 = 2;
const STORE_ONION: u8 = 3;

/// Length of the longest encoded invite: version, identity, key, store kind, and an onion
/// host with its length byte.
pub const MAX_INVITE_LEN: usize = 1 + IDENTITY_LEN + KEY_LEN + 1 + 1 + MAX_HOST_LEN;

/// Prefix of an invite's text form.
pub const TEXT_PREFIX: &str = "purple1";
/// Length of the longest invite's text form.
pub const MAX_TEXT_LEN: usize = TEXT_PREFIX.len() + 2 * MAX_INVITE_LEN;

/// Which store an invite's boxes live on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreRef {
    /// The self-test's in-memory network.
    Memory,
    /// A local purple-holodeck.
    Dev,
    /// Katzenpost's Namenlos network.
    Namenlos,
    /// A purple-memory-alpha onion service.
    Onion(String),
}

impl StoreRef {
    /// Parse the launcher's `--store` argument: `memory`, `dev`, `namenlos` or `tor:<onion>`.
    ///
    /// # Errors
    /// Fails on anything else.
    pub fn parse(arg: &str) -> Result<Self> {
        match arg {
            "memory" => Ok(Self::Memory),
            "dev" => Ok(Self::Dev),
            "namenlos" => Ok(Self::Namenlos),
            _ => match arg.strip_prefix("tor:") {
                Some(host) if valid_host(host) => Ok(Self::Onion(host.to_owned())),
                _ => Err(Error::Malformed("unknown store")),
            },
        }
    }

    /// For error messages.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Memory => "the in-memory test network".into(),
            Self::Dev => "the dev provider".into(),
            Self::Namenlos => "Namenlos".into(),
            Self::Onion(host) => host.clone(),
        }
    }
}

/// Printable ASCII, not empty, short enough for one length byte's worth of invite.
fn valid_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= MAX_HOST_LEN && host.bytes().all(|b| b.is_ascii_graphic())
}

/// What goes in the QR code or link.
#[derive(Clone)]
pub struct Invite {
    identity: IdentityKey,
    key: Zeroizing<[u8; KEY_LEN]>,
    /// `None` only for a version 1 invite read back from the vault.
    store: Option<StoreRef>,
}

impl fmt::Debug for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invite").finish_non_exhaustive()
    }
}

impl Invite {
    /// A new invite for `identity` on `store`, with a fresh key.
    pub(crate) fn create(identity: IdentityKey, store: StoreRef) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng
            .try_fill_bytes(key.as_mut_slice())
            .map_err(|_| Error::Malformed("OS random number generator failed"))?;
        Ok(Self {
            identity,
            key,
            store: Some(store),
        })
    }

    /// The store this invite's boxes live on; `None` for an old invite from the vault.
    #[must_use]
    pub const fn store(&self) -> Option<&StoreRef> {
        self.store.as_ref()
    }

    /// Encode for a QR code or link: version, identity key, invite key, then the store kind
    /// and, for an onion store, a length byte and the host. An old invite from the vault
    /// keeps its version 1 layout.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_INVITE_LEN));
        out.push(if self.store.is_some() {
            VERSION
        } else {
            OLD_VERSION
        });
        out.extend_from_slice(&self.identity.serialize());
        out.extend_from_slice(self.key.as_slice());
        match &self.store {
            None => {}
            Some(StoreRef::Memory) => out.push(STORE_MEMORY),
            Some(StoreRef::Dev) => out.push(STORE_DEV),
            Some(StoreRef::Namenlos) => out.push(STORE_NAMENLOS),
            Some(StoreRef::Onion(host)) => {
                out.push(STORE_ONION);
                // StoreRef::parse keeps hosts within MAX_HOST_LEN.
                out.push(u8::try_from(host.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(host.as_bytes());
            }
        }
        out
    }

    /// Decode a pasted or scanned invite. Version 1 invites don't say which store they're
    /// for, so they're refused.
    ///
    /// # Errors
    /// Fails on a bad length, an old or unknown version, an unknown store, or an invalid
    /// identity key.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.first() == Some(&OLD_VERSION) {
            return Err(Error::Malformed(
                "this invite is from an older purple; ask for a new one",
            ));
        }
        Self::decode_stored(bytes)
    }

    /// Decode an invite read back from the vault, which may be a version 1 invite made
    /// before invites named their store.
    ///
    /// # Errors
    /// As [`Invite::decode`], except that version 1 is accepted.
    pub fn decode_stored(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INVITE_LEN {
            return Err(Error::Malformed("invite is too long"));
        }
        let mut r = Reader(bytes);
        let [version] = r.take::<1>()?;
        let identity = IdentityKey::decode(&r.take::<IDENTITY_LEN>()?)?;
        let key = Zeroizing::new(r.take::<KEY_LEN>()?);
        let store = match version {
            OLD_VERSION => None,
            VERSION => Some(match r.take::<1>()? {
                [STORE_MEMORY] => StoreRef::Memory,
                [STORE_DEV] => StoreRef::Dev,
                [STORE_NAMENLOS] => StoreRef::Namenlos,
                [STORE_ONION] => {
                    let [len] = r.take::<1>()?;
                    let host = r.slice(usize::from(len))?;
                    let host = std::str::from_utf8(host)
                        .ok()
                        .filter(|host| valid_host(host))
                        .ok_or(Error::Malformed("invite has a bad store address"))?;
                    StoreRef::Onion(host.to_owned())
                }
                _ => return Err(Error::Malformed("invite names an unknown kind of store")),
            }),
            _ => return Err(Error::Malformed("unknown invite version")),
        };
        r.finish()?;
        Ok(Self {
            identity,
            key,
            store,
        })
    }

    /// Text form for pasting: [`TEXT_PREFIX`] followed by the encoded invite in lowercase hex.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(MAX_TEXT_LEN));
        out.push_str(TEXT_PREFIX);
        for byte in self.encode().iter() {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0F));
        }
        out
    }

    /// Parse the text form. Surrounding whitespace is ignored; hex may be either case.
    ///
    /// # Errors
    /// Fails on a missing prefix, non-hex characters, or an invalid invite.
    pub fn from_text(text: &str) -> Result<Self> {
        let hex = text
            .trim()
            .strip_prefix(TEXT_PREFIX)
            .ok_or(Error::Malformed("invite text must start with purple1"))?;
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            hex.as_bytes()
                .chunks(2)
                .map(|pair| match pair {
                    [high, low] => Ok(hex_value(*high)? << 4 | hex_value(*low)?),
                    _ => Err(Error::Malformed("invite text has an odd length")),
                })
                .collect::<Result<_>>()?,
        );
        Self::decode(&bytes)
    }

    /// Queue where the inviter stores the prekey bundle.
    pub(crate) fn bundle_queue(&self) -> Result<Queue> {
        QueueSecret::derive(self.key.as_slice(), b"bundle")?.queue()
    }

    /// Queue where the accepter sends the first message.
    pub(crate) fn intro_queue(&self) -> Result<Queue> {
        QueueSecret::derive(self.key.as_slice(), b"intro")?.queue()
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

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

fn hex_value(digit: u8) -> Result<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or(Error::Malformed("invite text has a non-hex character"))
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
        self.slice(len)
    }

    fn slice(&mut self, len: usize) -> Result<&'a [u8]> {
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

    fn test_invite(store: StoreRef) -> Invite {
        Account::generate().unwrap().create_invite(store).unwrap().0
    }

    /// The version 1 layout: version, identity, key.
    fn old_v1_bytes() -> Vec<u8> {
        let v2 = test_invite(StoreRef::Memory).encode();
        let mut v1 = vec![1];
        v1.extend_from_slice(&v2[1..1 + IDENTITY_LEN + KEY_LEN]);
        v1
    }

    #[test]
    fn invites_carry_their_store() {
        let onion = StoreRef::Onion(
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion".into(),
        );
        let invite = test_invite(onion.clone());
        let back = Invite::from_text(&invite.to_text()).unwrap();
        assert_eq!(back.store(), Some(&onion));
        for store in [StoreRef::Memory, StoreRef::Dev, StoreRef::Namenlos] {
            assert_eq!(
                Invite::decode(&test_invite(store.clone()).encode())
                    .unwrap()
                    .store(),
                Some(&store)
            );
        }
    }

    #[test]
    fn pasted_version_1_invites_are_refused_but_stored_ones_load() {
        let v1 = old_v1_bytes();
        let err = Invite::decode(&v1).unwrap_err();
        assert!(err.to_string().contains("older purple"), "{err}");
        assert_eq!(Invite::decode_stored(&v1).unwrap().store(), None);
    }

    #[test]
    fn store_refs_parse() {
        assert_eq!(StoreRef::parse("dev").unwrap(), StoreRef::Dev);
        assert_eq!(StoreRef::parse("namenlos").unwrap(), StoreRef::Namenlos);
        assert!(
            matches!(StoreRef::parse("tor:x.onion").unwrap(), StoreRef::Onion(h) if h == "x.onion")
        );
        assert!(StoreRef::parse("tor:").is_err());
        assert!(StoreRef::parse("carrier pigeon").is_err());
    }

    #[test]
    fn invite_fits_a_small_qr_code() {
        let invite = test_invite(StoreRef::Onion("a".repeat(56) + ".onion"));
        assert_eq!(invite.encode().len(), MAX_INVITE_LEN);
        assert_eq!(MAX_INVITE_LEN, 130);
    }

    #[test]
    fn accepted_invite_starts_a_session() {
        let mut bob = Account::generate().unwrap();
        let (invite, bundle) = bob.create_invite(StoreRef::Memory).unwrap();
        let scanned = Invite::decode(&invite.encode()).unwrap();
        assert_eq!(
            scanned.bundle_queue().unwrap().stream(),
            invite.bundle_queue().unwrap().stream()
        );

        let mut alice = Account::generate().unwrap();
        alice.accept_invite("bob", &scanned, &bundle).unwrap();
        let hello = alice.encrypt("bob", b"hello").unwrap();
        assert_eq!(bob.decrypt("alice", &hello).unwrap(), b"hello");
    }

    #[test]
    fn bundle_and_intro_queues_differ() {
        let (invite, _) = Account::generate()
            .unwrap()
            .create_invite(StoreRef::Memory)
            .unwrap();
        assert_ne!(
            invite.bundle_queue().unwrap().stream(),
            invite.intro_queue().unwrap().stream()
        );
    }

    #[test]
    fn rejects_malformed_invites() {
        let invite = test_invite(StoreRef::Onion("a".repeat(56) + ".onion"));
        let good = invite.encode();

        assert!(Invite::decode(&good[..good.len() - 1]).is_err());
        let mut long = good.to_vec();
        long.push(0);
        assert!(Invite::decode(&long).is_err());
        let mut wrong_kind = good.to_vec();
        wrong_kind[1 + IDENTITY_LEN + KEY_LEN] = 9;
        assert!(Invite::decode(&wrong_kind).is_err());
        let mut wrong_version = good.to_vec();
        wrong_version[0] = 3;
        assert!(Invite::decode(&wrong_version).is_err());
        let mut bad_identity = good.to_vec();
        bad_identity[1] = 0xFF;
        assert!(Invite::decode(&bad_identity).is_err());
    }

    #[test]
    fn text_form_round_trips_and_rejects_garbage() {
        let invite = test_invite(StoreRef::Dev);
        let text = invite.to_text();
        let text_len = text.len();
        assert!(text.starts_with(TEXT_PREFIX));
        assert!(text_len <= MAX_TEXT_LEN);
        let pasted = format!(
            "  {}\n",
            text.to_uppercase().replacen("PURPLE1", "purple1", 1)
        );
        assert_eq!(
            *Invite::from_text(&pasted).unwrap().encode(),
            *invite.encode()
        );

        let cut = |range: std::ops::Range<usize>| text.get(range).unwrap().to_owned();
        assert!(Invite::from_text(&cut(TEXT_PREFIX.len()..text_len)).is_err());
        assert!(Invite::from_text(&cut(0..text_len - 1)).is_err());
        assert!(Invite::from_text(&(cut(0..text_len - 2) + "zz")).is_err());
        assert!(Invite::from_text(&(cut(0..text_len - 2) + "é")).is_err());
    }

    #[test]
    fn rejects_truncated_or_padded_bundles() {
        let (invite, bundle) = Account::generate()
            .unwrap()
            .create_invite(StoreRef::Memory)
            .unwrap();
        assert!(invite.decode_bundle(&bundle[..bundle.len() - 1]).is_err());
        let mut padded = bundle;
        padded.push(0);
        assert!(invite.decode_bundle(&padded).is_err());
    }

    #[test]
    fn substituted_bundle_fails_identity_check() {
        // Someone who saw Bob's QR code can store their own prekeys in his bundle queue.
        // Their signatures don't match Bob's identity, so Alice refuses.
        let (invite, _) = Account::generate()
            .unwrap()
            .create_invite(StoreRef::Memory)
            .unwrap();
        let (_, mallory_bundle) = Account::generate()
            .unwrap()
            .create_invite(StoreRef::Memory)
            .unwrap();
        let mut alice = Account::generate().unwrap();
        assert!(
            alice
                .accept_invite("bob", &invite, &mallory_bundle)
                .is_err()
        );
    }
}
