//! Group credentials.
//!
//! A member's MLS credential is their purple identity key plus that
//! key's signature over their MLS signing key, so every member can check for themselves
//! that a leaf belongs to the identity it names. Without the signature, a creator could put
//! anyone's identity key on a key they hold.

use libsignal_protocol::IdentityKey;
use openmls::prelude::{BasicCredential, Credential, CredentialType, CredentialWithKey};

use crate::session::{Account, Error, Result};

const LABEL: &[u8] = b"purple mls signing key v1";
/// A serialized libsignal identity key: type byte and 32-byte key.
const IDENTITY_LEN: usize = 33;
const SIGNATURE_LEN: usize = 64;

/// The credential for `account` holding the MLS key `mls_public`.
///
/// # Errors
/// Fails if signing fails.
pub fn issue(account: &Account, mls_public: &[u8]) -> Result<CredentialWithKey> {
    let signature = account.sign(&[LABEL, mls_public].concat())?;
    let identity = account.identity_key().serialize();
    Ok(CredentialWithKey {
        credential: BasicCredential::new([&identity[..], &signature[..]].concat()).into(),
        signature_key: mls_public.to_vec().into(),
    })
}

/// The identity key that authorised `mls_public`, if `credential` proves it did.
///
/// # Errors
/// Fails if the credential is malformed or its signature doesn't cover `mls_public`.
pub fn verify(credential: &Credential, mls_public: &[u8]) -> Result<IdentityKey> {
    let (identity, signature) = parts(credential)?;
    if !identity
        .public_key()
        .verify_signature(&[LABEL, mls_public].concat(), signature)
    {
        return Err(Error::Malformed(
            "a member's identity key didn't authorise their group key",
        ));
    }
    Ok(identity)
}

/// The identity key a credential names, without checking its signature.
///
/// Only for a credential already verified when its leaf entered the group, such as the
/// sender credential OpenMLS hands back with a message.
///
/// # Errors
/// Fails if the credential is malformed.
pub fn identity(credential: &Credential) -> Result<IdentityKey> {
    parts(credential).map(|(identity, _)| identity)
}

fn parts(credential: &Credential) -> Result<(IdentityKey, &[u8])> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(Error::Malformed(
            "group credential isn't a basic credential",
        ));
    }
    let (identity, signature) = credential
        .serialized_content()
        .split_at_checked(IDENTITY_LEN)
        .ok_or(Error::Malformed("group credential too short"))?;
    if signature.len() != SIGNATURE_LEN {
        return Err(Error::Malformed("group credential has the wrong length"));
    }
    Ok((IdentityKey::decode(identity)?, signature))
}

#[cfg(test)]
mod tests {
    use openmls::prelude::BasicCredential;

    use super::*;
    use crate::mls::{Provider, SigningKey};

    #[test]
    fn a_credential_names_the_identity_that_signed_it() {
        let provider = Provider::new().unwrap();
        let account = Account::generate().unwrap();
        let key = SigningKey::generate(&provider).unwrap();
        let issued = issue(&account, key.public()).unwrap();
        assert_eq!(issued.signature_key.as_slice(), key.public());
        assert_eq!(
            verify(&issued.credential, key.public()).unwrap(),
            account.identity_key()
        );
    }

    #[test]
    fn a_forged_leaf_is_rejected() {
        // Mallory copies Bob's credential onto her own signing key.
        let provider = Provider::new().unwrap();
        let bob = Account::generate().unwrap();
        let bob_key = SigningKey::generate(&provider).unwrap();
        let mallory_key = SigningKey::generate(&provider).unwrap();
        let bobs = issue(&bob, bob_key.public()).unwrap();
        assert!(verify(&bobs.credential, mallory_key.public()).is_err());
    }

    #[test]
    fn tampered_and_malformed_credentials_are_rejected() {
        let provider = Provider::new().unwrap();
        let account = Account::generate().unwrap();
        let key = SigningKey::generate(&provider).unwrap();
        let mut bytes = issue(&account, key.public())
            .unwrap()
            .credential
            .serialized_content()
            .to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        for bad in [bytes.clone(), bytes[..IDENTITY_LEN].to_vec(), Vec::new()] {
            let credential = BasicCredential::new(bad).into();
            assert!(verify(&credential, key.public()).is_err());
        }
    }
}
