//! OpenMLS plumbing for groups: the crypto provider, per-group signing keys, group
//! configuration, and MLS state and messages as bytes.
//!
//! OpenMLS keeps all group state in its storage provider. purple uses the in-memory one and
//! writes every entry into the messenger snapshot, so group state lives in the vault with
//! everything else. The entries hold epoch secrets and private keys; they sit in ordinary
//! heap memory while purple runs, like libsignal's session records.

use std::fmt::{self, Display};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    Ciphersuite, KeyPackage, MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, MlsMessageOut, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, ProtocolMessage,
    ProtocolVersion, Welcome,
};
use openmls_libcrux_crypto::CryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::session::{Error, Result};

/// X-Wing (X25519 + ML-KEM-768) for confidentiality, Ed25519 for signatures. It has no IANA
/// code point yet, so only OpenMLS-based clients interoperate.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
/// Past epochs whose application messages still decrypt, so a message sent just before a
/// commit isn't lost.
pub const PAST_EPOCHS: usize = 2;
const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;

/// Wrap an OpenMLS error.
pub(crate) fn mls_error(err: impl Display) -> Error {
    Error::Mls(err.to_string())
}

fn poisoned<T>(_: T) -> Error {
    Error::State("MLS storage lock poisoned")
}

/// The libcrux crypto backend and in-memory storage that can be saved and restored.
pub(crate) struct Provider {
    crypto: CryptoProvider,
    storage: MemoryStorage,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider").finish_non_exhaustive()
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &CryptoProvider {
        &self.crypto
    }
}

impl Provider {
    /// A provider with empty storage.
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            crypto: CryptoProvider::new().map_err(mls_error)?,
            storage: MemoryStorage::default(),
        })
    }

    /// Write every storage entry, sorted, so equal state gives equal bytes.
    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        let values = self.storage.values.read().map_err(poisoned)?;
        let mut entries: Vec<_> = values.iter().collect();
        entries.sort();
        w.len(entries.len())?;
        for (key, value) in entries {
            w.bytes(key)?;
            w.bytes(value)?;
        }
        drop(values);
        Ok(())
    }

    /// Restore a provider written by [`Self::encode`].
    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let provider = Self::new()?;
        let mut values = provider.storage.values.write().map_err(poisoned)?;
        for _ in 0..r.len()? {
            let key = r.bytes()?.to_vec();
            let value = r.bytes()?.to_vec();
            if values.insert(key, value).is_some() {
                return Err(Error::Malformed("MLS storage entry repeated"));
            }
        }
        drop(values);
        Ok(provider)
    }
}

/// One group's MLS signing key. Each group gets its own; the member's credential ties it
/// to their purple identity key.
pub(crate) struct SigningKey {
    private: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

impl SigningKey {
    /// A fresh Ed25519 key.
    pub(crate) fn generate(provider: &Provider) -> Result<Self> {
        let (private, public) = provider
            .crypto
            .signature_key_gen(SIGNATURE_SCHEME)
            .map_err(mls_error)?;
        Ok(Self {
            private: Zeroizing::new(private),
            public,
        })
    }

    pub(crate) fn public(&self) -> &[u8] {
        &self.public
    }

    /// Something OpenMLS can sign with.
    pub(crate) const fn signer<'a>(&'a self, provider: &'a Provider) -> KeySigner<'a> {
        KeySigner {
            crypto: &provider.crypto,
            key: self,
        }
    }

    pub(crate) fn encode(&self, w: &mut Writer) -> Result<()> {
        w.bytes(&self.private)?;
        w.bytes(&self.public)
    }

    pub(crate) fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            private: Zeroizing::new(r.bytes()?.to_vec()),
            public: r.bytes()?.to_vec(),
        })
    }
}

/// A [`SigningKey`] lent to OpenMLS.
pub(crate) struct KeySigner<'a> {
    crypto: &'a CryptoProvider,
    key: &'a SigningKey,
}

impl Signer for KeySigner<'_> {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(SIGNATURE_SCHEME, payload, &self.key.private)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SIGNATURE_SCHEME
    }
}

/// How purple creates groups: the X-Wing suite, two past epochs, the ratchet tree inside
/// Welcomes (there's no server to fetch it from), and handshake messages encrypted too, so
/// commits don't show who is added or removed.
pub(crate) fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .max_past_epochs(PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// How purple joins groups; matches [`create_config`].
pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .max_past_epochs(PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// An MLS message (commit, Welcome, key package, application message) as bytes.
pub(crate) fn encode_message(message: impl Into<MlsMessageOut>) -> Result<Vec<u8>> {
    message.into().tls_serialize_detached().map_err(mls_error)
}

fn decode_body(bytes: &[u8]) -> Result<MlsMessageBodyIn> {
    Ok(MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(mls_error)?
        .extract())
}

/// A key package from bytes, with its signature and lifetime checked.
pub(crate) fn decode_key_package(provider: &Provider, bytes: &[u8]) -> Result<KeyPackage> {
    let MlsMessageBodyIn::KeyPackage(key_package) = decode_body(bytes)? else {
        return Err(Error::Malformed("expected an MLS key package"));
    };
    key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(mls_error)
}

/// A Welcome from bytes.
pub(crate) fn decode_welcome(bytes: &[u8]) -> Result<Welcome> {
    let MlsMessageBodyIn::Welcome(welcome) = decode_body(bytes)? else {
        return Err(Error::Malformed("expected an MLS Welcome"));
    };
    Ok(welcome)
}

/// A commit or application message from bytes.
pub(crate) fn decode_protocol(bytes: &[u8]) -> Result<ProtocolMessage> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(mls_error)?
        .try_into_protocol_message()
        .map_err(mls_error)
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{
        BasicCredential, CredentialWithKey, KeyPackage, MlsGroup, ProcessedMessageContent,
        StagedWelcome,
    };

    use super::*;

    fn credential(key: &SigningKey) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(b"test".to_vec()).into(),
            signature_key: key.public().to_vec().into(),
        }
    }

    fn secret(provider: &Provider, group: &MlsGroup) -> Vec<u8> {
        group
            .export_secret(provider.crypto(), "test", &[], 32)
            .unwrap()
    }

    #[test]
    fn group_state_survives_a_snapshot() {
        let provider = Provider::new().unwrap();
        let key = SigningKey::generate(&provider).unwrap();
        let group = MlsGroup::new(
            &provider,
            &key.signer(&provider),
            &create_config(),
            credential(&key),
        )
        .unwrap();

        let mut w = Writer::default();
        provider.encode(&mut w).unwrap();
        key.encode(&mut w).unwrap();
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let restored = Provider::decode(&mut r).unwrap();
        let restored_key = SigningKey::decode(&mut r).unwrap();
        r.finish().unwrap();

        let loaded = MlsGroup::load(restored.storage(), group.group_id())
            .unwrap()
            .unwrap();
        assert_eq!(secret(&provider, &group), secret(&restored, &loaded));
        assert_eq!(restored_key.public(), key.public());
    }

    #[test]
    fn key_packages_welcomes_and_messages_cross_as_bytes() {
        let (alice, bob) = (Provider::new().unwrap(), Provider::new().unwrap());
        let (alice_key, bob_key) = (
            SigningKey::generate(&alice).unwrap(),
            SigningKey::generate(&bob).unwrap(),
        );
        let mut group = MlsGroup::new(
            &alice,
            &alice_key.signer(&alice),
            &create_config(),
            credential(&alice_key),
        )
        .unwrap();

        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &bob,
                &bob_key.signer(&bob),
                credential(&bob_key),
            )
            .unwrap();
        let sent = encode_message(bundle.key_package().clone()).unwrap();
        let key_package = decode_key_package(&alice, &sent).unwrap();
        let (_, welcome, _) = group
            .add_members_without_update(&alice, &alice_key.signer(&alice), &[key_package])
            .unwrap();
        group.merge_pending_commit(&alice).unwrap();

        let welcome = decode_welcome(&encode_message(welcome).unwrap()).unwrap();
        let mut joined = StagedWelcome::new_from_welcome(&bob, &join_config(), welcome, None)
            .unwrap()
            .into_group(&bob)
            .unwrap();
        assert_eq!(secret(&alice, &group), secret(&bob, &joined));

        let message = group
            .create_message(&alice, &alice_key.signer(&alice), b"hi")
            .unwrap();
        let received = joined
            .process_message(
                &bob,
                decode_protocol(&encode_message(message).unwrap()).unwrap(),
            )
            .unwrap();
        let ProcessedMessageContent::ApplicationMessage(text) = received.into_content() else {
            panic!("not an application message");
        };
        assert_eq!(text.into_bytes(), b"hi");
    }

    #[test]
    fn garbage_and_the_wrong_kind_of_message_are_rejected() {
        let provider = Provider::new().unwrap();
        assert!(decode_key_package(&provider, &[1, 2, 3]).is_err());
        assert!(decode_welcome(&[]).is_err());
        let key = SigningKey::generate(&provider).unwrap();
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &provider,
                &key.signer(&provider),
                credential(&key),
            )
            .unwrap();
        let bytes = encode_message(bundle.key_package().clone()).unwrap();
        assert!(
            decode_welcome(&bytes).is_err(),
            "a key package isn't a Welcome"
        );
        assert!(decode_protocol(&bytes).is_err());
    }

    #[test]
    fn repeated_storage_entries_are_rejected() {
        let mut w = Writer::default();
        w.len(2).unwrap();
        for _ in 0..2 {
            w.bytes(b"k").unwrap();
            w.bytes(b"v").unwrap();
        }
        let bytes = w.finish();
        assert!(Provider::decode(&mut Reader::new(&bytes)).is_err());
    }
}
