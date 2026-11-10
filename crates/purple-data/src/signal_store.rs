//! purple's implementation of libsignal's storage traits, which unlike libsignal's
//! in-memory store can be saved to and restored from a snapshot.
//!
//! Peers are keyed by name only: purple has one device per account. One-time Kyber prekeys
//! are deleted as soon as a handshake uses them, so a replayed handshake can't succeed.

use std::collections::BTreeMap;

use async_trait::async_trait;
use libsignal_protocol::{
    Direction, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};

use crate::codec::{Reader, Writer};
use crate::session::{REGISTRATION_ID, Result};

type SignalResult<T> = std::result::Result<T, SignalProtocolError>;

/// Our identity and the identity keys we've seen for each peer.
pub(crate) struct Identities {
    own: IdentityKeyPair,
    known: BTreeMap<String, IdentityKey>,
}

/// One-time X25519 prekeys.
#[derive(Default)]
pub(crate) struct PreKeys(BTreeMap<u32, PreKeyRecord>);

/// Signed X25519 prekeys.
#[derive(Default)]
pub(crate) struct SignedPreKeys(BTreeMap<u32, SignedPreKeyRecord>);

/// Signed one-time ML-KEM prekeys.
#[derive(Default)]
pub(crate) struct KyberPreKeys(BTreeMap<u32, KyberPreKeyRecord>);

/// Ratchet state per peer.
#[derive(Default)]
pub(crate) struct Sessions(BTreeMap<String, SessionRecord>);

/// All of an account's libsignal state, split so each part can be borrowed mutably on its
/// own (libsignal takes them as separate `&mut dyn` arguments).
pub(crate) struct Stores {
    pub(crate) identities: Identities,
    pub(crate) pre_keys: PreKeys,
    pub(crate) signed_pre_keys: SignedPreKeys,
    pub(crate) kyber_pre_keys: KyberPreKeys,
    pub(crate) sessions: Sessions,
}

impl Stores {
    pub(crate) fn new(own: IdentityKeyPair) -> Self {
        Self {
            identities: Identities {
                own,
                known: BTreeMap::new(),
            },
            pre_keys: PreKeys::default(),
            signed_pre_keys: SignedPreKeys::default(),
            kyber_pre_keys: KyberPreKeys::default(),
            sessions: Sessions::default(),
        }
    }

    pub(crate) const fn identity(&self) -> &IdentityKeyPair {
        &self.identities.own
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.identities.own.serialize())?;
        w.len(self.identities.known.len())?;
        for (name, key) in &self.identities.known {
            w.bytes(name.as_bytes())?;
            w.bytes(&key.serialize())?;
        }
        w.len(self.pre_keys.0.len())?;
        for (id, record) in &self.pre_keys.0 {
            w.u32(*id);
            w.bytes(&record.serialize()?)?;
        }
        w.len(self.signed_pre_keys.0.len())?;
        for (id, record) in &self.signed_pre_keys.0 {
            w.u32(*id);
            w.bytes(&record.serialize()?)?;
        }
        w.len(self.kyber_pre_keys.0.len())?;
        for (id, record) in &self.kyber_pre_keys.0 {
            w.u32(*id);
            w.bytes(&record.serialize()?)?;
        }
        w.len(self.sessions.0.len())?;
        for (name, record) in &self.sessions.0 {
            w.bytes(name.as_bytes())?;
            w.bytes(&record.serialize()?)?;
        }
        Ok(())
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let own = IdentityKeyPair::try_from(r.bytes()?)?;
        let mut stores = Self::new(own);
        for _ in 0..r.len()? {
            let name = r.string()?;
            stores
                .identities
                .known
                .insert(name, IdentityKey::decode(r.bytes()?)?);
        }
        for _ in 0..r.len()? {
            let id = r.u32()?;
            stores
                .pre_keys
                .0
                .insert(id, PreKeyRecord::deserialize(r.bytes()?)?);
        }
        for _ in 0..r.len()? {
            let id = r.u32()?;
            stores
                .signed_pre_keys
                .0
                .insert(id, SignedPreKeyRecord::deserialize(r.bytes()?)?);
        }
        for _ in 0..r.len()? {
            let id = r.u32()?;
            stores
                .kyber_pre_keys
                .0
                .insert(id, KyberPreKeyRecord::deserialize(r.bytes()?)?);
        }
        for _ in 0..r.len()? {
            let name = r.string()?;
            stores
                .sessions
                .0
                .insert(name, SessionRecord::deserialize(r.bytes()?)?);
        }
        Ok(stores)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for Identities {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        Ok(self.own)
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        Ok(REGISTRATION_ID)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        match self.known.insert(address.name().to_owned(), *identity) {
            Some(old) if old != *identity => Ok(IdentityChange::ReplacedExisting),
            Some(_) | None => Ok(IdentityChange::NewOrUnchanged),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        // Trust on first use; after that only the same key.
        Ok(self
            .known
            .get(address.name())
            .is_none_or(|known| known == identity))
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        Ok(self.known.get(address.name()).copied())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PreKeys {
    async fn get_pre_key(&self, id: PreKeyId) -> SignalResult<PreKeyRecord> {
        self.0
            .get(&u32::from(id))
            .cloned()
            .ok_or(SignalProtocolError::InvalidPreKeyId)
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SignalResult<()> {
        self.0.insert(u32::from(id), record.clone());
        Ok(())
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> SignalResult<()> {
        self.0.remove(&u32::from(id));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SignedPreKeys {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SignalResult<SignedPreKeyRecord> {
        self.0
            .get(&u32::from(id))
            .cloned()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        self.0.insert(u32::from(id), record.clone());
        Ok(())
    }
}

impl SignedPreKeys {
    pub(crate) fn remove(&mut self, id: u32) {
        self.0.remove(&id);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for KyberPreKeys {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SignalResult<KyberPreKeyRecord> {
        self.0
            .get(&u32::from(id))
            .cloned()
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)
    }

    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        self.0.insert(u32::from(id), record.clone());
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        _signed_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> SignalResult<()> {
        // Every purple Kyber prekey is one-time (one per invite), so delete it.
        self.0.remove(&u32::from(id));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for Sessions {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        Ok(self.0.get(address.name()).cloned())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        self.0.insert(address.name().to_owned(), record.clone());
        Ok(())
    }
}
