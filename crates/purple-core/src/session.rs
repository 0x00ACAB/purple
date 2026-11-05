//! 1:1 sessions: a PQXDH handshake, then libsignal's triple ratchet (the double ratchet
//! combined with the SPQR post-quantum ratchet).
//!
//! Wire format of an encrypted message: one tag byte ([`TAG_PREKEY`] or [`TAG_WHISPER`]),
//! then libsignal's serialized message.

use std::fmt;
use std::time::SystemTime;

use futures_executor::block_on;
use libsignal_protocol::kem::KeyType;
use libsignal_protocol::{
    CiphertextMessage, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, ProtocolAddress, SignalMessage,
    SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    message_decrypt, message_encrypt, process_prekey_bundle,
};
use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::codec::{Reader, Writer};
use crate::invite::{Invite, encode_bundle};
use crate::signal_store::Stores;

/// libsignal puts the registration ID in the clear inside `PreKey` messages, and Signal uses
/// a random one per install. A constant leaks nothing about who sent the message.
pub(crate) const REGISTRATION_ID: u32 = 1;
/// purple has one device per account. Like the registration ID, a constant leaks nothing.
const DEVICE_ID: u8 = 1;
/// Name of the local account in libsignal's stores. Peers are named by the caller.
const LOCAL_NAME: &str = "self";

/// Wire tag of a message that carries the PQXDH handshake.
pub const TAG_PREKEY: u8 = 1;
/// Wire tag of an ordinary ratchet message.
pub const TAG_WHISPER: u8 = 2;

/// Errors from establishing sessions or encrypting and decrypting messages.
#[derive(Debug)]
pub enum Error {
    /// libsignal rejected the operation: bad signature, untrusted identity, replay, etc.
    Signal(SignalProtocolError),
    /// The bytes aren't something purple accepts.
    Malformed(&'static str),
    /// Fragment reassembly or another I/O-level step failed.
    Io(std::io::Error),
    /// A name, invite or contact the call refers to doesn't exist or is already taken.
    State(&'static str),
    /// OpenMLS rejected a group operation; its own description of why.
    Mls(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(err) => write!(f, "signal protocol: {err}"),
            Self::Malformed(msg) => write!(f, "malformed: {msg}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::State(msg) => f.write_str(msg),
            Self::Mls(msg) => write!(f, "group: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<SignalProtocolError> for Error {
    fn from(err: SignalProtocolError) -> Self {
        Self::Signal(err)
    }
}

/// Result type for this module.
pub type Result<T> = std::result::Result<T, Error>;

/// One user's identity, prekeys and sessions with their contacts.
pub struct Account {
    stores: Stores,
    local: ProtocolAddress,
    next_prekey_id: u32,
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account").finish_non_exhaustive()
    }
}

impl Account {
    /// Create an account with a fresh identity key pair.
    ///
    /// # Errors
    /// Fails if libsignal can't set up its store.
    pub fn generate() -> Result<Self> {
        let identity = IdentityKeyPair::generate(&mut rng());
        Ok(Self {
            stores: Stores::new(identity),
            local: address(LOCAL_NAME)?,
            next_prekey_id: 1,
        })
    }

    /// Generate a one-time set of prekeys (X25519 one-time, signed X25519, signed
    /// ML-KEM-1024), store the private halves, and return the public bundle for an invite.
    ///
    /// # Errors
    /// Fails if signing or storing the prekeys fails.
    pub fn new_prekey_bundle(&mut self) -> Result<PreKeyBundle> {
        let mut rng = rng();
        let id = self.take_prekey_id()?;
        let identity = *self.stores.identity();

        let one_time = KeyPair::generate(&mut rng);
        let signed = KeyPair::generate(&mut rng);
        let signed_signature = identity
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), &mut rng)
            .map_err(SignalProtocolError::from)?;
        let kyber = KyberPreKeyRecord::generate(
            KeyType::Kyber1024,
            KyberPreKeyId::from(id),
            identity.private_key(),
        )?;

        block_on(self.stores.pre_keys.save_pre_key(
            PreKeyId::from(id),
            &PreKeyRecord::new(PreKeyId::from(id), &one_time),
        ))?;
        block_on(self.stores.signed_pre_keys.save_signed_pre_key(
            SignedPreKeyId::from(id),
            &SignedPreKeyRecord::new(
                SignedPreKeyId::from(id),
                now_timestamp(),
                &signed,
                &signed_signature,
            ),
        ))?;
        block_on(
            self.stores
                .kyber_pre_keys
                .save_kyber_pre_key(KyberPreKeyId::from(id), &kyber),
        )?;

        Ok(PreKeyBundle::new(
            REGISTRATION_ID,
            device_id()?,
            Some((PreKeyId::from(id), one_time.public_key)),
            SignedPreKeyId::from(id),
            signed.public_key,
            signed_signature.into_vec(),
            KyberPreKeyId::from(id),
            kyber.public_key()?,
            kyber.signature()?,
            *identity.identity_key(),
        )?)
    }

    /// Create a one-time invite. Returns the invite for the QR code or link, and the
    /// encoded prekey bundle to store in the invite's bundle queue.
    ///
    /// # Errors
    /// Fails if generating the prekeys fails.
    pub fn create_invite(&mut self) -> Result<(Invite, Vec<u8>)> {
        let bundle = self.new_prekey_bundle()?;
        let identity = *self.stores.identity().identity_key();
        Ok((Invite::create(identity)?, encode_bundle(&bundle)?))
    }

    /// This account's public identity key.
    #[must_use]
    pub fn identity_key(&self) -> IdentityKey {
        *self.stores.identity().identity_key()
    }

    /// Sign `message` with the identity key (XEdDSA).
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Box<[u8]>> {
        Ok(self
            .stores
            .identity()
            .private_key()
            .calculate_signature(message, &mut rng())
            .map_err(SignalProtocolError::from)?)
    }

    /// The identity key libsignal has for `peer`, once a session with them exists.
    ///
    /// # Errors
    /// Fails only if `peer` isn't a valid address.
    pub fn peer_identity(&self, peer: &str) -> Result<Option<IdentityKey>> {
        Ok(block_on(
            self.stores.identities.get_identity(&address(peer)?),
        )?)
    }

    /// Accept `invite` using the bundle fetched from its bundle queue, and start a session
    /// with `peer`.
    ///
    /// # Errors
    /// Fails if the bundle is malformed, or its signatures don't match the invite's
    /// identity key.
    pub fn accept_invite(&mut self, peer: &str, invite: &Invite, bundle: &[u8]) -> Result<()> {
        self.start_session(peer, &invite.decode_bundle(bundle)?)
    }

    /// Start a session with `peer` from the bundle in their invite. The first message
    /// encrypted to `peer` afterwards carries the PQXDH handshake.
    ///
    /// # Errors
    /// Fails if a signature in the bundle is invalid, or if `peer` is already known under
    /// a different identity key.
    pub fn start_session(&mut self, peer: &str, bundle: &PreKeyBundle) -> Result<()> {
        let peer = address(peer)?;
        block_on(process_prekey_bundle(
            &peer,
            &self.local,
            &mut self.stores.sessions,
            &mut self.stores.identities,
            bundle,
            SystemTime::now(),
            &mut rng(),
        ))?;
        Ok(())
    }

    /// Encrypt `plaintext` for `peer` and advance the ratchet.
    ///
    /// # Errors
    /// Fails if there's no session with `peer`.
    pub fn encrypt(&mut self, peer: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let peer = address(peer)?;
        let message = block_on(message_encrypt(
            plaintext,
            &peer,
            &self.local,
            &mut self.stores.sessions,
            &mut self.stores.identities,
            SystemTime::now(),
            &mut rng(),
        ))?;
        let tag = match &message {
            CiphertextMessage::PreKeySignalMessage(_) => TAG_PREKEY,
            CiphertextMessage::SignalMessage(_) => TAG_WHISPER,
            CiphertextMessage::SenderKeyMessage(_) | CiphertextMessage::PlaintextContent(_) => {
                return Err(Error::Malformed(
                    "libsignal produced an unexpected message type",
                ));
            }
        };
        let mut wire = Vec::with_capacity(message.serialize().len().saturating_add(1));
        wire.push(tag);
        wire.extend_from_slice(message.serialize());
        Ok(wire)
    }

    /// Decrypt a message from `peer` and advance the ratchet. A `PreKey` message also
    /// completes the handshake and consumes the one-time prekeys it used.
    ///
    /// # Errors
    /// Fails if the message is malformed, tampered with, replayed, or from an identity
    /// other than the one already known for `peer`.
    pub fn decrypt(&mut self, peer: &str, wire: &[u8]) -> Result<Vec<u8>> {
        let peer = address(peer)?;
        let (&tag, body) = wire
            .split_first()
            .ok_or(Error::Malformed("empty message"))?;
        let message = match tag {
            TAG_PREKEY => {
                CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(body)?)
            }
            TAG_WHISPER => CiphertextMessage::SignalMessage(SignalMessage::try_from(body)?),
            _ => return Err(Error::Malformed("unknown message tag")),
        };
        let plaintext = block_on(message_decrypt(
            &message,
            &peer,
            &self.local,
            &mut self.stores.sessions,
            &mut self.stores.identities,
            &mut self.stores.pre_keys,
            &self.stores.signed_pre_keys,
            &mut self.stores.kyber_pre_keys,
            &mut rng(),
        ))?;
        Ok(plaintext)
    }

    #[cfg(test)]
    fn snapshot(&self) -> Self {
        let mut w = Writer::default();
        self.encode(&mut w).unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let copy = Self::decode(&mut r).unwrap();
        r.finish().unwrap();
        copy
    }

    /// Write the account's whole state (identity, prekeys, sessions) into a snapshot.
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        w.u32(self.next_prekey_id);
        self.stores.encode(w)
    }

    /// Restore an account written by [`Self::encode`].
    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let next_prekey_id = r.u32()?;
        Ok(Self {
            stores: Stores::decode(r)?,
            local: address(LOCAL_NAME)?,
            next_prekey_id,
        })
    }

    fn take_prekey_id(&mut self) -> Result<u32> {
        let id = self.next_prekey_id;
        self.next_prekey_id = id
            .checked_add(1)
            .ok_or(Error::Malformed("prekey IDs exhausted"))?;
        Ok(id)
    }
}

/// Key material comes straight from the OS. `unwrap_err` panics if the OS RNG fails,
/// which is the only safe response: there is no fallback for missing entropy.
fn rng() -> impl rand::CryptoRng {
    OsRng.unwrap_err()
}

pub(crate) fn device_id() -> Result<DeviceId> {
    DeviceId::new(DEVICE_ID).map_err(|_| Error::Malformed("invalid device ID"))
}

fn address(name: &str) -> Result<ProtocolAddress> {
    Ok(ProtocolAddress::new(name.to_owned(), device_id()?))
}

fn now_timestamp() -> Timestamp {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    Timestamp::from_epoch_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alice starts a session from Bob's bundle and sends the first message.
    fn connected() -> (Account, Account) {
        let mut alice = Account::generate().unwrap();
        let mut bob = Account::generate().unwrap();
        let bundle = bob.new_prekey_bundle().unwrap();
        alice.start_session("bob", &bundle).unwrap();
        let first = alice.encrypt("bob", b"hi bob").unwrap();
        assert_eq!(first[0], TAG_PREKEY);
        assert_eq!(bob.decrypt("alice", &first).unwrap(), b"hi bob");
        (alice, bob)
    }

    #[test]
    fn peers_identity_keys_are_known_once_connected() {
        let (alice, bob) = connected();
        assert_eq!(
            alice.peer_identity("bob").unwrap(),
            Some(bob.identity_key())
        );
        assert_eq!(alice.peer_identity("carol").unwrap(), None);
    }

    #[test]
    fn handshake_then_messages_both_ways() {
        let (mut alice, mut bob) = connected();
        let reply = bob.encrypt("alice", b"hi alice").unwrap();
        assert_eq!(reply[0], TAG_WHISPER);
        assert_eq!(alice.decrypt("bob", &reply).unwrap(), b"hi alice");

        for i in 0u8..20 {
            let to_bob = alice.encrypt("bob", &[i]).unwrap();
            assert_eq!(bob.decrypt("alice", &to_bob).unwrap(), [i]);
            let to_alice = bob.encrypt("alice", &[i, i]).unwrap();
            assert_eq!(alice.decrypt("bob", &to_alice).unwrap(), [i, i]);
        }
    }

    #[test]
    fn out_of_order_delivery_decrypts() {
        let (mut alice, mut bob) = connected();
        let sent: Vec<_> = (0u8..5)
            .map(|i| alice.encrypt("bob", &[i]).unwrap())
            .collect();
        for (i, wire) in sent.iter().enumerate().rev() {
            assert_eq!(
                bob.decrypt("alice", wire).unwrap(),
                [u8::try_from(i).unwrap()]
            );
        }
    }

    #[test]
    fn replay_is_rejected() {
        let (mut alice, mut bob) = connected();
        let wire = alice.encrypt("bob", b"once").unwrap();
        bob.decrypt("alice", &wire).unwrap();
        assert!(bob.decrypt("alice", &wire).is_err());
    }

    /// Flip every byte after the tag, one at a time, and decrypt with a fresh copy of Bob.
    /// Returns the plaintexts of the copies that accepted a flipped message.
    fn accepted_after_bit_flips(bob: &Account, wire: &[u8]) -> Vec<Vec<u8>> {
        (1..wire.len())
            .filter_map(|i| {
                let mut flipped = wire.to_vec();
                flipped[i] ^= 1;
                bob.snapshot().decrypt("alice", &flipped).ok()
            })
            .collect()
    }

    #[test]
    fn tampered_ratchet_message_is_always_rejected() {
        let (mut alice, mut bob) = connected();
        alice
            .decrypt("bob", &bob.encrypt("alice", b"ack").unwrap())
            .unwrap();
        let wire = alice.encrypt("bob", b"intact").unwrap();
        assert_eq!(wire[0], TAG_WHISPER);
        assert!(accepted_after_bit_flips(&bob, &wire).is_empty());
    }

    #[test]
    fn tampered_prekey_message_never_changes_plaintext() {
        // Until Bob replies, Alice keeps sending PreKey messages. Once Bob has the session he
        // ignores their outer fields (registration ID, prekey IDs, Kyber ciphertext), so
        // flips there are accepted. The inner message is still authenticated: no flip may
        // ever produce a different plaintext.
        let (mut alice, bob) = connected();
        let wire = alice.encrypt("bob", b"intact").unwrap();
        assert_eq!(wire[0], TAG_PREKEY);
        for plaintext in accepted_after_bit_flips(&bob, &wire) {
            assert_eq!(plaintext, b"intact");
        }
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        let (mut alice, mut bob) = connected();
        let mut wire = alice.encrypt("bob", b"x").unwrap();
        wire[0] = 0xFF;
        assert!(matches!(
            bob.decrypt("alice", &wire),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            bob.decrypt("alice", &[]),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn prekey_bundle_is_single_use() {
        let mut bob = Account::generate().unwrap();
        let bundle = bob.new_prekey_bundle().unwrap();

        let mut alice = Account::generate().unwrap();
        alice.start_session("bob", &bundle).unwrap();
        bob.decrypt("alice", &alice.encrypt("bob", b"first").unwrap())
            .unwrap();

        // A second account replaying the same bundle can't get its handshake accepted,
        // because Bob already consumed the one-time and Kyber prekeys.
        let mut mallory = Account::generate().unwrap();
        mallory.start_session("bob", &bundle).unwrap();
        assert!(
            bob.decrypt("mallory", &mallory.encrypt("bob", b"again").unwrap())
                .is_err()
        );
    }

    #[test]
    fn changed_identity_is_rejected() {
        let (mut alice, _) = connected();
        let mut impostor = Account::generate().unwrap();
        let bundle = impostor.new_prekey_bundle().unwrap();
        assert!(matches!(
            alice.start_session("bob", &bundle),
            Err(Error::Signal(SignalProtocolError::UntrustedIdentity(_)))
        ));
    }

    #[test]
    fn forged_bundle_signature_is_rejected() {
        let mut bob = Account::generate().unwrap();
        let other = Account::generate().unwrap();
        let bundle = bob.new_prekey_bundle().unwrap();
        // Bob's prekeys presented under someone else's identity: the signatures don't match.
        let other_identity = *other.stores.identity().identity_key();
        let forged = bundle
            .modify(|content| content.identity_key = Some(other_identity))
            .unwrap();
        let mut alice = Account::generate().unwrap();
        assert!(alice.start_session("bob", &forged).is_err());
    }
}
