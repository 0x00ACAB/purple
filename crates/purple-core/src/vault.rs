//! On-disk storage: the encrypted state snapshot and the encrypted message history.
//!
//! A random 32-byte data key, held in a [`SecretPage`] (`memfd_secret` where available),
//! encrypts everything; HKDF splits it into a state key and a history key. The data key
//! never changes. Key slots in the state header each hold a wrapped copy of it
//! (XChaCha20-Poly1305 under a key-encryption key). A new vault has a passphrase slot,
//! keyed by Argon2id. Enrolling the TPM replaces it with a TPM slot, keyed by Argon2id
//! together with a secret only the TPM releases, and a recovery slot, keyed by a random
//! code shown once. With no passphrase slot left, a copy of the disk can't be attacked
//! offline: every guess has to go through the TPM, which rate-limits them. Changing the
//! passphrase only rewraps the data key, so history is never rewritten.
//!
//! `state.purple`: header (magic, version, key slots), nonce, then the snapshot sealed under
//! the state key with the whole header as AAD. Each save writes a temporary file, syncs it,
//! and renames it over the old one, so a crash leaves either the old state or the new one.
//! Slots of a kind this version doesn't understand are kept exactly as they are.
//!
//! `history.purple`: header (magic, version), then records, each a u32 length, a nonce and
//! a sealed entry. A record's AAD is its index, so records can't be reordered or dropped
//! from the middle undetected. A record cut short by a crash is truncated on open.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use purple_harden::secret::{Protection, SecretPage};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::session::{Error, Result};
use crate::tpm::{SECRET_LEN, Sealer};

const STATE_FILE: &str = "state.purple";
const STATE_TMP: &str = "state.purple.tmp";
const HISTORY_FILE: &str = "history.purple";
const LOCK_FILE: &str = "lock";
const STATE_MAGIC: &[u8; 8] = b"PURPLE\0S";
const HISTORY_MAGIC: &[u8; 8] = b"PURPLE\0H";
const STATE_VERSION: u8 = 2;
const HISTORY_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;
const HISTORY_HEADER_LEN: usize = 8 + 1;
/// Largest history record accepted when reading.
const MAX_RECORD_LEN: usize = 1 << 20;

/// Key slot kinds.
const SLOT_PASSPHRASE: u8 = 1;
const SLOT_TPM: u8 = 2;
const SLOT_RECOVERY: u8 = 3;
/// Length of a recovery code's secret.
const RECOVERY_LEN: usize = 16;
/// RFC 4648 base32, which survives being read aloud or written by hand.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Characters in a recovery code, without separators: 128 bits at 5 per character.
const RECOVERY_CHARS: usize = 26;
#[cfg(test)]
/// A passphrase slot: Argon2 parameters, salt, nonce, wrapped data key.
const PASSPHRASE_SLOT_LEN: usize = 4 + 4 + 4 + SALT_LEN + NONCE_LEN + WRAPPED_LEN;

/// Shortest passphrase accepted, in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 8;

/// Argon2id cost parameters, stored in each passphrase slot so they can change later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes over memory.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl KdfParams {
    /// 256 MiB, 3 passes, 1 lane: roughly a second on a desktop.
    pub const DEFAULT: Self = Self {
        memory_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    };
}

/// One message in the history log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The contact the message was exchanged with.
    pub contact: String,
    /// Whether this user sent it.
    pub outgoing: bool,
    /// Unix seconds.
    pub at: u64,
    /// Message text.
    pub body: Vec<u8>,
}

/// The data key wrapped under a key derived from a passphrase.
#[derive(Clone)]
struct PassphraseSlot {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl PassphraseSlot {
    /// Wrap `data_key` under `passphrase` with a fresh salt and nonce.
    fn wrap(data_key: &SecretPage, passphrase: &str, params: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let kek = derive_kek(passphrase, &salt, params)?;
        let (nonce, wrapped) = wrap_key(kek.as_slice(), data_key, &Self::aad(params, &salt))?;
        Ok(Self {
            params,
            salt,
            nonce,
            wrapped,
        })
    }

    /// Recover the data key. Fails on a wrong passphrase.
    fn unwrap(&self, passphrase: &str) -> Result<SecretPage> {
        let kek = derive_kek(passphrase, &self.salt, self.params)?;
        unwrap_key(
            kek.as_slice(),
            &self.nonce,
            &self.wrapped,
            &Self::aad(self.params, &self.salt),
            "wrong passphrase, or the state file is damaged",
        )
    }

    /// Binds the wrapped key to the file format, slot kind and Argon2 inputs.
    fn aad(params: KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
        slot_aad(SLOT_PASSPHRASE, &[&encode_params(params), salt])
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&encode_params(self.params));
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }

    fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let slot = Self {
            params: decode_params(&mut r)?,
            salt: r.take()?,
            nonce: r.take()?,
            wrapped: r.take()?,
        };
        r.finish()?;
        Ok(slot)
    }
}

/// The data key wrapped under a key that needs both the passphrase and a secret sealed in
/// the TPM. The TPM releases the secret only for a password derived from the passphrase,
/// and counts wrong ones toward its lockout.
#[derive(Clone)]
struct TpmSlot {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    /// The TPM's sealed object holding the secret.
    sealed: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl TpmSlot {
    /// Wrap `data_key` under `passphrase` and a fresh secret sealed in `sealer`.
    fn wrap(
        data_key: &SecretPage,
        passphrase: &str,
        params: KdfParams,
        sealer: &mut dyn Sealer,
    ) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let stretched = derive_kek(passphrase, &salt, params)?;
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        fill_random(secret.as_mut_slice())?;
        let object = sealer.seal(&*tpm_auth(&stretched)?, &secret)?;
        let kek = tpm_kek(&stretched, &secret)?;
        let (nonce, wrapped) =
            wrap_key(kek.as_slice(), data_key, &Self::aad(params, &salt, &object))?;
        Ok(Self {
            params,
            salt,
            sealed: object,
            nonce,
            wrapped,
        })
    }

    /// Recover the data key. A wrong passphrase is caught by the TPM.
    fn unwrap(&self, passphrase: &str, sealer: &mut dyn Sealer) -> Result<SecretPage> {
        let stretched = derive_kek(passphrase, &self.salt, self.params)?;
        let secret = sealer.unseal(&self.sealed, &*tpm_auth(&stretched)?)?;
        let kek = tpm_kek(&stretched, &secret)?;
        unwrap_key(
            kek.as_slice(),
            &self.nonce,
            &self.wrapped,
            &Self::aad(self.params, &self.salt, &self.sealed),
            "the state file is damaged",
        )
    }

    fn aad(params: KdfParams, salt: &[u8; SALT_LEN], sealed: &[u8]) -> Vec<u8> {
        slot_aad(SLOT_TPM, &[&encode_params(params), salt, sealed])
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&encode_params(self.params));
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
        let len = u16::try_from(self.sealed.len())
            .map_err(|_| Error::Malformed("sealed TPM object too long"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.sealed);
        Ok(())
    }

    fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let params = decode_params(&mut r)?;
        let salt = r.take()?;
        let nonce = r.take()?;
        let wrapped = r.take()?;
        let len = usize::from(u16::from_be_bytes(r.take()?));
        let slot = Self {
            params,
            salt,
            sealed: r.raw(len)?.to_vec(),
            nonce,
            wrapped,
        };
        r.finish()?;
        Ok(slot)
    }
}

/// The data key wrapped under a key derived from a [`RecoveryCode`]. The code has 128 bits
/// of entropy, so HKDF is enough; it needs no stretching.
#[derive(Clone)]
struct RecoverySlot {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl RecoverySlot {
    fn wrap(data_key: &SecretPage, code: &RecoveryCode) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let kek = recovery_kek(code, &salt)?;
        let (nonce, wrapped) = wrap_key(kek.as_slice(), data_key, &Self::aad(&salt))?;
        Ok(Self {
            salt,
            nonce,
            wrapped,
        })
    }

    fn unwrap(&self, code: &RecoveryCode) -> Result<SecretPage> {
        let kek = recovery_kek(code, &self.salt)?;
        unwrap_key(
            kek.as_slice(),
            &self.nonce,
            &self.wrapped,
            &Self::aad(&self.salt),
            "wrong recovery code",
        )
    }

    fn aad(salt: &[u8; SALT_LEN]) -> Vec<u8> {
        slot_aad(SLOT_RECOVERY, &[salt])
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }

    fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let slot = Self {
            salt: r.take()?,
            nonce: r.take()?,
            wrapped: r.take()?,
        };
        r.finish()?;
        Ok(slot)
    }
}

/// A random code that opens the vault without the TPM, shown once when the TPM is
/// enrolled. Written as base32 in dash-separated groups.
pub struct RecoveryCode(Zeroizing<[u8; RECOVERY_LEN]>);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(..)")
    }
}

impl RecoveryCode {
    fn generate() -> Result<Self> {
        let mut code = Zeroizing::new([0u8; RECOVERY_LEN]);
        fill_random(code.as_mut_slice())?;
        Ok(Self(code))
    }

    /// The code as the user writes it down: five groups, the last one six characters.
    #[must_use]
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut chars = Zeroizing::new(String::with_capacity(RECOVERY_CHARS));
        let mut bits: u32 = 0;
        let mut held = 0u32;
        for &byte in self.0.iter() {
            bits = (bits << 8) | u32::from(byte);
            held = held.saturating_add(8);
            while held >= 5 {
                held = held.saturating_sub(5);
                chars.push(base32_char(bits >> held));
            }
        }
        if held > 0 {
            chars.push(base32_char(bits << (5u32.saturating_sub(held))));
        }
        let mut text = Zeroizing::new(String::with_capacity(RECOVERY_CHARS + 4));
        for (i, c) in chars.chars().enumerate() {
            if i > 0 && i % 5 == 0 && i < RECOVERY_CHARS - 1 {
                text.push('-');
            }
            text.push(c);
        }
        text
    }

    /// Read a code back, ignoring case, spaces and dashes. `None` if `text` isn't one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut code = Zeroizing::new([0u8; RECOVERY_LEN]);
        let mut bits: u32 = 0;
        let mut held = 0u32;
        let mut out = 0usize;
        let mut chars = 0usize;
        for c in text.chars().filter(|c| !matches!(c, '-' | ' ')) {
            let value = BASE32
                .iter()
                .position(|&b| char::from(b) == c.to_ascii_uppercase())?;
            chars = chars.saturating_add(1);
            bits = (bits << 5) | u32::try_from(value).ok()?;
            held = held.saturating_add(5);
            if held >= 8 {
                held = held.saturating_sub(8);
                *code.get_mut(out)? = u8::try_from((bits >> held) & 0xFF).ok()?;
                out = out.saturating_add(1);
            }
        }
        // 26 characters carry 130 bits; the last two must be zero.
        if chars != RECOVERY_CHARS || out != RECOVERY_LEN || bits & !(u32::MAX << held) != 0 {
            return None;
        }
        Some(Self(code))
    }
}

fn base32_char(index: u32) -> char {
    let index = usize::try_from(index & 0x1F).unwrap_or(0);
    char::from(*BASE32.get(index).unwrap_or(&b'A'))
}

/// How the vault was unlocked this time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockedBy {
    /// With the passphrase alone.
    Passphrase,
    /// With the passphrase and the TPM.
    Tpm,
    /// With the recovery code.
    RecoveryCode,
}

/// The state file header: key slots. There is always a passphrase slot or a TPM slot.
struct Header {
    passphrase: Option<PassphraseSlot>,
    tpm: Option<TpmSlot>,
    recovery: Option<RecoverySlot>,
    /// Slots of kinds this version doesn't understand, kept as (kind, body).
    unknown_slots: Vec<(u8, Vec<u8>)>,
}

impl Header {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut slots: Vec<(u8, Vec<u8>)> = Vec::new();
        if let Some(slot) = &self.passphrase {
            let mut body = Vec::new();
            slot.encode(&mut body);
            slots.push((SLOT_PASSPHRASE, body));
        }
        if let Some(slot) = &self.tpm {
            let mut body = Vec::new();
            slot.encode(&mut body)?;
            slots.push((SLOT_TPM, body));
        }
        if let Some(slot) = &self.recovery {
            let mut body = Vec::new();
            slot.encode(&mut body);
            slots.push((SLOT_RECOVERY, body));
        }
        slots.extend(self.unknown_slots.iter().cloned());
        let count =
            u8::try_from(slots.len()).map_err(|_| Error::Malformed("too many key slots"))?;
        let mut out = Vec::new();
        out.extend_from_slice(STATE_MAGIC);
        out.push(STATE_VERSION);
        out.push(count);
        for (kind, body) in slots {
            let len =
                u16::try_from(body.len()).map_err(|_| Error::Malformed("key slot too long"))?;
            out.push(kind);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&body);
        }
        Ok(out)
    }

    /// Parse the header at the start of `file`. Returns it and its length in bytes.
    fn decode(file: &[u8]) -> Result<(Self, usize)> {
        let mut r = Reader::new(file);
        if r.take::<8>()? != *STATE_MAGIC {
            return Err(Error::Malformed("not a purple state file"));
        }
        match r.u8()? {
            STATE_VERSION => {}
            1 => {
                return Err(Error::State(
                    "this vault uses format 1 from an earlier purple build; delete the data \
                     directory and create a new vault",
                ));
            }
            _ => return Err(Error::Malformed("state file is from a newer purple")),
        }
        let mut header = Self {
            passphrase: None,
            tpm: None,
            recovery: None,
            unknown_slots: Vec::new(),
        };
        for _ in 0..r.u8()? {
            let kind = r.u8()?;
            let len = usize::from(u16::from_be_bytes(r.take()?));
            let body = r.raw(len)?;
            let duplicate = match kind {
                SLOT_PASSPHRASE => header
                    .passphrase
                    .replace(PassphraseSlot::decode(body)?)
                    .is_some(),
                SLOT_TPM => header.tpm.replace(TpmSlot::decode(body)?).is_some(),
                SLOT_RECOVERY => header
                    .recovery
                    .replace(RecoverySlot::decode(body)?)
                    .is_some(),
                _ => {
                    header.unknown_slots.push((kind, body.to_vec()));
                    false
                }
            };
            if duplicate {
                return Err(Error::Malformed("duplicate key slot"));
            }
        }
        if header.passphrase.is_none() && header.tpm.is_none() {
            return Err(Error::Malformed("no passphrase or TPM slot"));
        }
        Ok((header, file.len().saturating_sub(r.rest().len())))
    }

    /// Recover the data key from `secret`: the recovery code if it is one, otherwise the
    /// passphrase, through the TPM if the vault is sealed to it.
    fn unlock(
        &self,
        secret: &str,
        sealer: Option<&mut dyn Sealer>,
    ) -> Result<(SecretPage, UnlockedBy)> {
        if let (Some(slot), Some(code)) = (&self.recovery, RecoveryCode::parse(secret))
            && let Ok(data_key) = slot.unwrap(&code)
        {
            return Ok((data_key, UnlockedBy::RecoveryCode));
        }
        if let Some(slot) = &self.passphrase {
            return Ok((slot.unwrap(secret)?, UnlockedBy::Passphrase));
        }
        let slot = self
            .tpm
            .as_ref()
            .ok_or(Error::Malformed("no passphrase or TPM slot"))?;
        let sealer = sealer.ok_or(Error::State(
            "this vault is sealed to a TPM that purple can't reach; use the recovery code",
        ))?;
        Ok((slot.unwrap(secret, sealer)?, UnlockedBy::Tpm))
    }
}

/// An unlocked vault directory. Holds the directory lock while it exists.
pub struct Vault {
    dir: PathBuf,
    data_key: SecretPage,
    header: Header,
    unlocked_by: UnlockedBy,
    history_records: u64,
    _lock: File,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.dir)
            .field("protection", &self.data_key.protection())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Whether `dir` already holds a vault.
    #[must_use]
    pub fn exists(dir: &Path) -> bool {
        dir.join(STATE_FILE).exists()
    }

    /// Create a new vault in `dir` with a fresh data key, and save `snapshot` as its first
    /// state. Any history left from an earlier vault is discarded, since it can't be
    /// decrypted anyway.
    ///
    /// # Errors
    /// Fails if the passphrase is too short, a vault already exists, another purple holds
    /// the directory, or writing fails.
    pub fn create(
        dir: &Path,
        passphrase: &str,
        params: KdfParams,
        snapshot: &[u8],
    ) -> Result<Self> {
        check_passphrase(passphrase)?;
        let lock = lock_dir(dir)?;
        if Self::exists(dir) {
            return Err(Error::State("a vault already exists here"));
        }
        let mut data_key = SecretPage::new(KEY_LEN)?;
        fill_random(data_key.as_mut_slice())?;
        let header = Header {
            passphrase: Some(PassphraseSlot::wrap(&data_key, passphrase, params)?),
            tpm: None,
            recovery: None,
            unknown_slots: Vec::new(),
        };
        let mut history = create_private(&dir.join(HISTORY_FILE))?;
        history.write_all(HISTORY_MAGIC)?;
        history.write_all(&[HISTORY_VERSION])?;
        history.sync_all()?;
        let vault = Self {
            dir: dir.to_owned(),
            data_key,
            header,
            unlocked_by: UnlockedBy::Passphrase,
            history_records: 0,
            _lock: lock,
        };
        vault.save(snapshot)?;
        Ok(vault)
    }

    /// Unlock the vault in `dir` with its passphrase or recovery code. `sealer` is the TPM,
    /// needed if the vault is sealed to it. Returns the vault with the saved snapshot.
    ///
    /// # Errors
    /// Fails on a wrong passphrase, if the TPM is needed but missing or refuses, on a
    /// damaged or unsupported file, or if another purple holds the directory.
    pub fn open(
        dir: &Path,
        passphrase: &str,
        sealer: Option<&mut dyn Sealer>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let lock = lock_dir(dir)?;
        let file = Zeroizing::new(fs::read(dir.join(STATE_FILE))?);
        let (header, header_len) = Header::decode(&file)?;
        let (header_bytes, rest) = file
            .split_at_checked(header_len)
            .ok_or(Error::Malformed("state file too short"))?;
        let (data_key, unlocked_by) = header.unlock(passphrase, sealer)?;
        let (nonce, ciphertext) = rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::Malformed("state file too short"))?;
        let snapshot = cipher(&data_key, b"purple state key")?
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: header_bytes,
                },
            )
            .map_err(|_| Error::Malformed("the state file is damaged"))?;

        let mut vault = Self {
            dir: dir.to_owned(),
            data_key,
            header,
            unlocked_by,
            history_records: 0,
            _lock: lock,
        };
        vault.history_records = vault
            .scan_history()?
            .len()
            .try_into()
            .map_err(|_| Error::Malformed("history too long"))?;
        Ok((vault, Zeroizing::new(snapshot)))
    }

    /// Replace the passphrase. `old` must be the current one, or the recovery code. With
    /// the recovery code, a TPM slot is dropped for a plain passphrase slot, since the TPM
    /// may be what was lost. Only key slots change: the data key, and so the history, stay
    /// as they are. `snapshot` is saved with the new header.
    ///
    /// # Errors
    /// Fails if `old` is wrong, `new` is too short, the TPM is needed but missing or
    /// refuses, or saving fails. The vault is unchanged on failure.
    pub fn change_passphrase(
        &mut self,
        old: &str,
        new: &str,
        params: KdfParams,
        snapshot: &[u8],
        sealer: Option<&mut dyn Sealer>,
    ) -> Result<()> {
        check_passphrase(new)?;
        let recovered = match (&self.header.recovery, RecoveryCode::parse(old)) {
            (Some(slot), Some(code)) => slot.unwrap(&code).is_ok(),
            _ => false,
        };
        if recovered {
            let passphrase = PassphraseSlot::wrap(&self.data_key, new, params)?;
            let recovery = self.header.recovery.clone();
            return self.replace_slots(Some(passphrase), None, recovery, snapshot);
        }
        if let Some(slot) = &self.header.passphrase {
            slot.unwrap(old)?;
            let passphrase = PassphraseSlot::wrap(&self.data_key, new, params)?;
            let (tpm, recovery) = (self.header.tpm.clone(), self.header.recovery.clone());
            return self.replace_slots(Some(passphrase), tpm, recovery, snapshot);
        }
        let slot = self
            .header
            .tpm
            .as_ref()
            .ok_or(Error::Malformed("no passphrase or TPM slot"))?;
        let sealer = sealer.ok_or(Error::State(
            "changing the passphrase needs the TPM, which purple can't reach",
        ))?;
        slot.unwrap(old, &mut *sealer)?;
        let tpm = TpmSlot::wrap(&self.data_key, new, params, sealer)?;
        let recovery = self.header.recovery.clone();
        self.replace_slots(None, Some(tpm), recovery, snapshot)
    }

    /// Seal the vault to the TPM: the passphrase slot gives way to a TPM slot under the same
    /// passphrase and a recovery slot. Returns the recovery code, to be shown once.
    ///
    /// # Errors
    /// Fails if the vault is already sealed, `passphrase` is wrong, the TPM refuses, or
    /// saving fails. The vault is unchanged on failure.
    pub fn enroll_tpm(
        &mut self,
        passphrase: &str,
        params: KdfParams,
        snapshot: &[u8],
        sealer: &mut dyn Sealer,
    ) -> Result<RecoveryCode> {
        let slot = self
            .header
            .passphrase
            .as_ref()
            .ok_or(Error::State("this vault is already sealed to the TPM"))?;
        slot.unwrap(passphrase)?;
        let tpm = TpmSlot::wrap(&self.data_key, passphrase, params, sealer)?;
        // Make sure the TPM gives the secret back before the passphrase slot goes.
        tpm.unwrap(passphrase, sealer)?;
        let code = RecoveryCode::generate()?;
        let recovery = RecoverySlot::wrap(&self.data_key, &code)?;
        self.replace_slots(None, Some(tpm), Some(recovery), snapshot)?;
        Ok(code)
    }

    /// Put these slots in the header and save. On failure the old slots come back.
    fn replace_slots(
        &mut self,
        passphrase: Option<PassphraseSlot>,
        tpm: Option<TpmSlot>,
        recovery: Option<RecoverySlot>,
        snapshot: &[u8],
    ) -> Result<()> {
        let previous = (
            std::mem::replace(&mut self.header.passphrase, passphrase),
            std::mem::replace(&mut self.header.tpm, tpm),
            std::mem::replace(&mut self.header.recovery, recovery),
        );
        if let Err(err) = self.save(snapshot) {
            (
                self.header.passphrase,
                self.header.tpm,
                self.header.recovery,
            ) = previous;
            return Err(err);
        }
        Ok(())
    }

    /// How the vault was unlocked.
    #[must_use]
    pub const fn unlocked_by(&self) -> UnlockedBy {
        self.unlocked_by
    }

    /// Whether the vault is sealed to the TPM.
    #[must_use]
    pub const fn sealed_to_tpm(&self) -> bool {
        self.header.tpm.is_some()
    }

    /// How the data key is protected in memory.
    #[must_use]
    pub const fn protection(&self) -> Protection {
        self.data_key.protection()
    }

    /// Replace the saved state with `snapshot`, atomically.
    ///
    /// # Errors
    /// Fails if encryption or writing fails. The old state is untouched on failure.
    pub fn save(&self, snapshot: &[u8]) -> Result<()> {
        let header = self.header.encode()?;
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let ciphertext = cipher(&self.data_key, b"purple state key")?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: snapshot,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Malformed("state encryption failed"))?;

        let tmp = self.dir.join(STATE_TMP);
        let mut file = create_private(&tmp)?;
        file.write_all(&header)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        fs::rename(&tmp, self.dir.join(STATE_FILE))?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Every history entry, oldest first.
    ///
    /// # Errors
    /// Fails if a complete record doesn't decrypt (tampering or damage).
    pub fn history(&self) -> Result<Vec<HistoryEntry>> {
        self.scan_history()
    }

    /// Append one entry to the history log and sync it to disk.
    ///
    /// # Errors
    /// Fails if encryption or writing fails.
    pub fn append(&mut self, entry: &HistoryEntry) -> Result<()> {
        let mut w = Writer::default();
        w.bytes(entry.contact.as_bytes())?;
        w.u8(u8::from(entry.outgoing));
        w.u64(entry.at);
        w.bytes(&entry.body)?;
        let plaintext = w.finish();

        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let ciphertext = cipher(&self.data_key, b"purple history key")?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &self.history_records.to_be_bytes(),
                },
            )
            .map_err(|_| Error::Malformed("history encryption failed"))?;
        let len = u32::try_from(NONCE_LEN.saturating_add(ciphertext.len()))
            .map_err(|_| Error::Malformed("history record too long"))?;

        let mut record =
            Vec::with_capacity(4usize.saturating_add(usize::try_from(len).unwrap_or(0)));
        record.extend_from_slice(&len.to_be_bytes());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.dir.join(HISTORY_FILE))?;
        file.write_all(&record)?;
        file.sync_data()?;
        self.history_records = self
            .history_records
            .checked_add(1)
            .ok_or(Error::Malformed("history too long"))?;
        Ok(())
    }

    /// Read and decrypt the history log, truncating a final record cut short by a crash.
    fn scan_history(&self) -> Result<Vec<HistoryEntry>> {
        let path = self.dir.join(HISTORY_FILE);
        let mut bytes = Vec::new();
        File::open(&path)?.read_to_end(&mut bytes)?;
        let (header, mut rest) = bytes
            .split_at_checked(HISTORY_HEADER_LEN)
            .ok_or(Error::Malformed("history file too short"))?;
        let mut r = Reader::new(header);
        if r.take::<8>()? != *HISTORY_MAGIC || r.u8()? != HISTORY_VERSION {
            return Err(Error::Malformed(
                "not a purple history file, or a newer version",
            ));
        }

        let cipher = cipher(&self.data_key, b"purple history key")?;
        let mut entries = Vec::new();
        let mut index: u64 = 0;
        let mut good_len = HISTORY_HEADER_LEN;
        while !rest.is_empty() {
            let Some((len, after_len)) = rest.split_first_chunk::<4>() else {
                break;
            };
            let len = usize::try_from(u32::from_be_bytes(*len))
                .map_err(|_| Error::Malformed("history record too long"))?;
            if len > MAX_RECORD_LEN {
                return Err(Error::Malformed("history record too long"));
            }
            let Some((record, after_record)) = after_len.split_at_checked(len) else {
                break;
            };
            let (nonce, ciphertext) = record
                .split_first_chunk::<NONCE_LEN>()
                .ok_or(Error::Malformed("history record too short"))?;
            let plaintext = Zeroizing::new(
                cipher
                    .decrypt(
                        &XNonce::from(*nonce),
                        Payload {
                            msg: ciphertext,
                            aad: &index.to_be_bytes(),
                        },
                    )
                    .map_err(|_| Error::Malformed("history record failed to decrypt"))?,
            );
            let mut entry = Reader::new(&plaintext);
            entries.push(HistoryEntry {
                contact: entry.string()?,
                outgoing: entry.u8()? != 0,
                at: entry.u64()?,
                body: entry.bytes()?.to_vec(),
            });
            entry.finish()?;

            index = index
                .checked_add(1)
                .ok_or(Error::Malformed("history too long"))?;
            good_len = good_len.saturating_add(4).saturating_add(len);
            rest = after_record;
        }
        if good_len < bytes.len() {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(
                u64::try_from(good_len).map_err(|_| Error::Malformed("history too long"))?,
            )?;
            file.sync_all()?;
        }
        Ok(entries)
    }
}

fn check_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(Error::State("passphrase must be at least 8 characters"));
    }
    Ok(())
}

/// Argon2id: passphrase to key-encryption key.
fn derive_kek(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<SecretPage> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Malformed("invalid Argon2 parameters"))?;
    let mut kek = SecretPage::new(KEY_LEN)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|_| Error::Malformed("Argon2 failed"))?;
    Ok(kek)
}

fn key_cipher(kek: &[u8]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|_| Error::Malformed("invalid key-encryption key"))
}

/// Wrap `data_key` under `kek` with a fresh nonce, bound to `aad`.
fn wrap_key(
    kek: &[u8],
    data_key: &SecretPage,
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], [u8; WRAPPED_LEN])> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    let wrapped = key_cipher(kek)?
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: data_key.as_slice(),
                aad,
            },
        )
        .map_err(|_| Error::Malformed("wrapping the data key failed"))?;
    let wrapped = wrapped
        .try_into()
        .map_err(|_| Error::Malformed("wrapped key has the wrong length"))?;
    Ok((nonce, wrapped))
}

/// Recover a data key wrapped by [`wrap_key`]. `wrong` is the error when it doesn't open.
fn unwrap_key(
    kek: &[u8],
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_LEN],
    aad: &[u8],
    wrong: &'static str,
) -> Result<SecretPage> {
    let plaintext = Zeroizing::new(
        key_cipher(kek)?
            .decrypt(&XNonce::from(*nonce), Payload { msg: wrapped, aad })
            .map_err(|_| Error::State(wrong))?,
    );
    let mut data_key = SecretPage::new(KEY_LEN)?;
    data_key.as_mut_slice().copy_from_slice(
        plaintext
            .get(..KEY_LEN)
            .ok_or(Error::Malformed("short data key"))?,
    );
    Ok(data_key)
}

/// A slot's AAD: the file format, the slot kind, then `fields`, the last of which may vary
/// in length.
fn slot_aad(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(STATE_MAGIC);
    aad.extend_from_slice(&[STATE_VERSION, kind]);
    for field in fields {
        aad.extend_from_slice(field);
    }
    aad
}

fn encode_params(params: KdfParams) -> [u8; 12] {
    let mut out = [0u8; 12];
    for (chunk, value) in
        out.chunks_exact_mut(4)
            .zip([params.memory_kib, params.iterations, params.parallelism])
    {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    out
}

fn decode_params(r: &mut Reader<'_>) -> Result<KdfParams> {
    Ok(KdfParams {
        memory_kib: r.u32()?,
        iterations: r.u32()?,
        parallelism: r.u32()?,
    })
}

/// The TPM object's password, from the stretched passphrase.
fn tpm_auth(stretched: &SecretPage) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
    let mut auth = Zeroizing::new([0u8; SECRET_LEN]);
    Hkdf::<Sha256>::new(None, stretched.as_slice())
        .expand(b"purple vault tpm auth v1", auth.as_mut_slice())
        .map_err(|_| Error::Malformed("HKDF output length invalid"))?;
    Ok(auth)
}

/// The TPM slot's key-encryption key: needs both the stretched passphrase and the secret
/// the TPM keeps.
fn tpm_kek(stretched: &SecretPage, secret: &[u8; SECRET_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(KEY_LEN + SECRET_LEN));
    ikm.extend_from_slice(stretched.as_slice());
    ikm.extend_from_slice(secret);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(b"purple vault tpm kek v1", kek.as_mut_slice())
        .map_err(|_| Error::Malformed("HKDF output length invalid"))?;
    Ok(kek)
}

fn recovery_kek(code: &RecoveryCode, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(salt), code.0.as_slice())
        .expand(b"purple vault recovery kek v1", kek.as_mut_slice())
        .map_err(|_| Error::Malformed("HKDF output length invalid"))?;
    Ok(kek)
}

/// A cipher keyed by HKDF from the data key, one per `label`.
fn cipher(data_key: &SecretPage, label: &[u8]) -> Result<XChaCha20Poly1305> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, data_key.as_slice())
        .expand(label, key.as_mut_slice())
        .map_err(|_| Error::Malformed("HKDF output length invalid"))?;
    XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| Error::Malformed("invalid storage key"))
}

/// Take an exclusive lock on `dir`, so two purple instances never write the same vault.
fn lock_dir(dir: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))?;
    lock.try_lock()
        .map_err(|_| Error::State("another purple is already using this data directory"))?;
    Ok(lock)
}

fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(out)
        .map_err(|_| Error::Malformed("OS random number generator failed"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// Cheap parameters so tests run fast. Never use these for real.
    const FAST: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("purple-vault-test-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entry(contact: &str, body: &str) -> HistoryEntry {
        HistoryEntry {
            contact: contact.into(),
            outgoing: false,
            at: 1,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn create_save_and_reopen() {
        let dir = temp_dir("reopen");
        let vault = Vault::create(&dir, "correct horse", FAST, b"first").unwrap();
        vault.save(b"second").unwrap();
        drop(vault);

        let (_vault, snapshot) = Vault::open(&dir, "correct horse", None).unwrap();
        assert_eq!(snapshot.as_slice(), b"second");
        let mode = fs::metadata(dir.join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.join(STATE_TMP).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_passphrase_short_passphrase_and_tampering_fail() {
        let dir = temp_dir("wrong");
        assert!(Vault::create(&dir, "short", FAST, b"x").is_err());
        drop(Vault::create(&dir, "correct horse", FAST, b"secret state").unwrap());
        assert!(Vault::open(&dir, "wrong horse!", None).is_err());

        let path = dir.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        // Any byte, header included, is authenticated.
        // Magic, version, slot count, slot kind and length, slot body.
        let header_len = 8 + 1 + 1 + 1 + 2 + PASSPHRASE_SLOT_LEN;
        for i in [0, 9, header_len - 1, header_len, bytes.len() - 1] {
            bytes[i] ^= 1;
            fs::write(&path, &bytes).unwrap();
            assert!(
                Vault::open(&dir, "correct horse", None).is_err(),
                "byte {i}"
            );
            bytes[i] ^= 1;
        }
        fs::write(&path, &bytes).unwrap();
        assert!(Vault::open(&dir, "correct horse", None).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_file_hides_the_snapshot() {
        let dir = temp_dir("hides");
        drop(Vault::create(&dir, "correct horse", FAST, b"very secret words").unwrap());
        let bytes = fs::read(dir.join(STATE_FILE)).unwrap();
        assert!(!bytes.windows(17).any(|w| w == b"very secret words"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_one_instance_per_directory() {
        let dir = temp_dir("lock");
        let _held = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        assert!(Vault::open(&dir, "correct horse", None).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn history_appends_reopens_and_recovers_from_a_torn_write() {
        let dir = temp_dir("history");
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        vault.append(&entry("alice", "one")).unwrap();
        vault.append(&entry("bob", "two")).unwrap();
        drop(vault);

        // A crash mid-append leaves a partial record at the end.
        let path = dir.join(HISTORY_FILE);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0, 0, 0, 200, 1, 2, 3]).unwrap();
        drop(file);

        let (mut reopened, _) = Vault::open(&dir, "correct horse", None).unwrap();
        assert_eq!(
            reopened.history().unwrap(),
            [entry("alice", "one"), entry("bob", "two")]
        );
        reopened.append(&entry("alice", "three")).unwrap();
        assert_eq!(reopened.history().unwrap().len(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn change_passphrase_rewraps_without_touching_history() {
        let dir = temp_dir("rewrap");
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"state").unwrap();
        vault.append(&entry("alice", "kept")).unwrap();
        let history_before = fs::read(dir.join(HISTORY_FILE)).unwrap();

        vault
            .change_passphrase("correct horse", "battery staple", FAST, b"state 2", None)
            .unwrap();
        drop(vault);

        assert_eq!(fs::read(dir.join(HISTORY_FILE)).unwrap(), history_before);
        assert!(Vault::open(&dir, "correct horse", None).is_err());
        let (reopened, snapshot) = Vault::open(&dir, "battery staple", None).unwrap();
        assert_eq!(snapshot.as_slice(), b"state 2");
        assert_eq!(reopened.history().unwrap(), [entry("alice", "kept")]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_passphrase_change_leaves_the_vault_as_it_was() {
        let dir = temp_dir("rewrap-fail");
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"state").unwrap();
        assert!(
            vault
                .change_passphrase("wrong horse!", "battery staple", FAST, b"x", None)
                .is_err()
        );
        assert!(
            vault
                .change_passphrase("correct horse", "short", FAST, b"x", None)
                .is_err()
        );
        vault.save(b"still works").unwrap();
        drop(vault);
        let (_vault, snapshot) = Vault::open(&dir, "correct horse", None).unwrap();
        assert_eq!(snapshot.as_slice(), b"still works");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_key_slots_survive_saves() {
        let dir = temp_dir("slots");
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        vault.header.unknown_slots.push((9, vec![1, 2, 3]));
        vault.save(b"y").unwrap();
        drop(vault);
        let (reopened, snapshot) = Vault::open(&dir, "correct horse", None).unwrap();
        assert_eq!(snapshot.as_slice(), b"y");
        assert_eq!(reopened.header.unknown_slots, [(9, vec![1, 2, 3])]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn format_one_vaults_get_a_clear_error() {
        let dir = temp_dir("v1");
        let mut old = STATE_MAGIC.to_vec();
        old.push(1);
        old.extend_from_slice(&[0; 64]);
        fs::write(dir.join(STATE_FILE), old).unwrap();
        let err = Vault::open(&dir, "correct horse", None).unwrap_err();
        assert!(err.to_string().contains("format 1"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reordered_history_is_rejected() {
        let dir = temp_dir("reorder");
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        vault.append(&entry("alice", "same length A")).unwrap();
        vault.append(&entry("alice", "same length B")).unwrap();
        let path = dir.join(HISTORY_FILE);
        let bytes = fs::read(&path).unwrap();
        let body = &bytes[HISTORY_HEADER_LEN..];
        let (first, second) = body.split_at(body.len() / 2);
        fs::write(
            &path,
            [&bytes[..HISTORY_HEADER_LEN], second, first].concat(),
        )
        .unwrap();
        assert!(vault.history().is_err());
        fs::remove_dir_all(&dir).ok();
    }

    /// A TPM stand-in: keeps secrets in memory and locks out after three wrong passwords.
    #[derive(Default)]
    struct FakeTpm {
        objects: Vec<([u8; SECRET_LEN], [u8; SECRET_LEN])>,
        failures: u32,
        refuse_seal: bool,
    }

    impl Sealer for FakeTpm {
        fn seal(&mut self, auth: &[u8; SECRET_LEN], secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>> {
            if self.refuse_seal {
                return Err(Error::State("TPM refused"));
            }
            self.objects.push((*auth, *secret));
            Ok(self.objects.len().saturating_sub(1).to_be_bytes().to_vec())
        }

        fn unseal(
            &mut self,
            sealed: &[u8],
            auth: &[u8; SECRET_LEN],
        ) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
            if self.failures >= 3 {
                return Err(Error::State("locked out"));
            }
            let index = usize::from_be_bytes(
                sealed
                    .try_into()
                    .map_err(|_| Error::Malformed("not a sealed object"))?,
            );
            let (expected, secret) = *self
                .objects
                .get(index)
                .ok_or(Error::Malformed("no such object"))?;
            if expected != *auth {
                self.failures = self.failures.saturating_add(1);
                return Err(Error::State("wrong passphrase"));
            }
            Ok(Zeroizing::new(secret))
        }
    }

    fn slot_kinds(dir: &Path) -> Vec<u8> {
        let file = fs::read(dir.join(STATE_FILE)).unwrap();
        let (header, _) = Header::decode(&file).unwrap();
        let mut kinds = Vec::new();
        if header.passphrase.is_some() {
            kinds.push(SLOT_PASSPHRASE);
        }
        if header.tpm.is_some() {
            kinds.push(SLOT_TPM);
        }
        if header.recovery.is_some() {
            kinds.push(SLOT_RECOVERY);
        }
        kinds
    }

    #[test]
    fn enrolling_the_tpm_leaves_nothing_to_attack_offline() {
        let dir = temp_dir("tpm");
        let mut tpm = FakeTpm::default();
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"state 1").unwrap();
        vault.append(&entry("alice", "kept")).unwrap();
        assert!(
            vault
                .enroll_tpm("wrong horse!", FAST, b"state 1", &mut tpm)
                .is_err()
        );
        let code = vault
            .enroll_tpm("correct horse", FAST, b"state 2", &mut tpm)
            .unwrap();
        assert!(vault.sealed_to_tpm());
        assert_eq!(slot_kinds(&dir), [SLOT_TPM, SLOT_RECOVERY]);
        assert!(
            vault
                .enroll_tpm("correct horse", FAST, b"x", &mut tpm)
                .is_err(),
            "already sealed"
        );
        drop(vault);

        // The right passphrase alone no longer opens it.
        let err = Vault::open(&dir, "correct horse", None).unwrap_err();
        assert!(err.to_string().contains("recovery code"), "{err}");
        let (sealed, snapshot) = Vault::open(&dir, "correct horse", Some(&mut tpm)).unwrap();
        assert_eq!(snapshot.as_slice(), b"state 2");
        assert_eq!(sealed.unlocked_by(), UnlockedBy::Tpm);
        assert_eq!(sealed.history().unwrap(), [entry("alice", "kept")]);
        drop(sealed);

        // Wrong guesses go through the TPM, which counts them.
        for _ in 0..3 {
            assert!(Vault::open(&dir, "wrong horse!", Some(&mut tpm)).is_err());
        }
        let locked = Vault::open(&dir, "correct horse", Some(&mut tpm)).unwrap_err();
        assert_eq!(locked.to_string(), "locked out");

        // The recovery code still opens it, TPM or not.
        let (recovered, recovered_snapshot) = Vault::open(&dir, &code.to_text(), None).unwrap();
        assert_eq!(recovered_snapshot.as_slice(), b"state 2");
        assert_eq!(recovered.unlocked_by(), UnlockedBy::RecoveryCode);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recovery_resets_the_vault_to_a_plain_passphrase() {
        let dir = temp_dir("recover");
        let mut tpm = FakeTpm::default();
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        let code = vault
            .enroll_tpm("correct horse", FAST, b"x", &mut tpm)
            .unwrap();
        drop(vault);

        // The TPM is gone: unlock with the code, then pick a new passphrase.
        let (mut recovered, _) = Vault::open(&dir, &code.to_text().to_lowercase(), None).unwrap();
        recovered
            .change_passphrase(&code.to_text(), "battery staple", FAST, b"y", None)
            .unwrap();
        assert!(!recovered.sealed_to_tpm());
        assert_eq!(slot_kinds(&dir), [SLOT_PASSPHRASE, SLOT_RECOVERY]);
        drop(recovered);
        let (reopened, snapshot) = Vault::open(&dir, "battery staple", None).unwrap();
        assert_eq!(snapshot.as_slice(), b"y");
        assert_eq!(reopened.unlocked_by(), UnlockedBy::Passphrase);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn changing_the_passphrase_reseals_it_in_the_tpm() {
        let dir = temp_dir("reseal");
        let mut tpm = FakeTpm::default();
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        vault
            .enroll_tpm("correct horse", FAST, b"x", &mut tpm)
            .unwrap();
        assert!(
            vault
                .change_passphrase("correct horse", "battery staple", FAST, b"x", None)
                .is_err(),
            "needs the TPM"
        );
        vault
            .change_passphrase(
                "correct horse",
                "battery staple",
                FAST,
                b"y",
                Some(&mut tpm),
            )
            .unwrap();
        assert_eq!(slot_kinds(&dir), [SLOT_TPM, SLOT_RECOVERY]);
        drop(vault);
        assert!(Vault::open(&dir, "correct horse", Some(&mut tpm)).is_err());
        let (reopened, _) = Vault::open(&dir, "battery staple", Some(&mut tpm)).unwrap();
        assert_eq!(reopened.unlocked_by(), UnlockedBy::Tpm);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_refusing_tpm_leaves_the_vault_as_it_was() {
        let dir = temp_dir("refuse");
        let mut tpm = FakeTpm {
            refuse_seal: true,
            ..FakeTpm::default()
        };
        let mut vault = Vault::create(&dir, "correct horse", FAST, b"x").unwrap();
        assert!(
            vault
                .enroll_tpm("correct horse", FAST, b"x", &mut tpm)
                .is_err()
        );
        assert!(!vault.sealed_to_tpm());
        assert_eq!(slot_kinds(&dir), [SLOT_PASSPHRASE]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recovery_codes_read_back_however_they_are_typed() {
        let code = RecoveryCode::generate().unwrap();
        let text = code.to_text();
        assert_eq!(text.len(), RECOVERY_CHARS + 4);
        assert_eq!(
            text.split('-').map(str::len).collect::<Vec<_>>(),
            [5, 5, 5, 5, 6]
        );
        for typed in [
            text.to_string(),
            text.to_lowercase(),
            text.replace('-', " "),
            text.replace('-', ""),
        ] {
            assert_eq!(*RecoveryCode::parse(&typed).unwrap().0, *code.0, "{typed}");
        }
        let zeros = RecoveryCode(Zeroizing::new([0; RECOVERY_LEN]));
        assert_eq!(*zeros.to_text(), "AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA");
        assert!(RecoveryCode::parse("correct horse battery staple").is_none());
        let short: String = text.chars().skip(1).collect();
        assert!(RecoveryCode::parse(&short).is_none());
        // The last character carries two bits that must be zero.
        assert!(RecoveryCode::parse("AAAAA-AAAAA-AAAAA-AAAAA-AAAAAB").is_none());
        assert!(RecoveryCode::parse("AAAAA-AAAAA-AAAAA-AAAAA-AAAAAE").is_some());
    }
}
