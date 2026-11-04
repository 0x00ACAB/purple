//! On-disk storage: the encrypted state snapshot and the encrypted message history.
//!
//! A random 32-byte data key, held in a [`SecretPage`] (`memfd_secret` where available),
//! encrypts everything; HKDF splits it into a state key and a history key. The data key
//! never changes. Key slots in the state header each hold a wrapped copy of it: for now one
//! passphrase slot (Argon2id, then XChaCha20-Poly1305), later a TPM slot beside it.
//! Changing the passphrase only rewraps the data key, so history is never rewritten.
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
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let kek = derive_kek(passphrase, &salt, params)?;
        let wrapped = key_cipher(&kek)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: data_key.as_slice(),
                    aad: &Self::aad(params, &salt),
                },
            )
            .map_err(|_| Error::Malformed("wrapping the data key failed"))?;
        Ok(Self {
            params,
            salt,
            nonce,
            wrapped: wrapped
                .try_into()
                .map_err(|_| Error::Malformed("wrapped key has the wrong length"))?,
        })
    }

    /// Recover the data key. Fails on a wrong passphrase.
    fn unwrap(&self, passphrase: &str) -> Result<SecretPage> {
        let kek = derive_kek(passphrase, &self.salt, self.params)?;
        let plaintext = Zeroizing::new(
            key_cipher(&kek)?
                .decrypt(
                    &XNonce::from(self.nonce),
                    Payload {
                        msg: &self.wrapped,
                        aad: &Self::aad(self.params, &self.salt),
                    },
                )
                .map_err(|_| Error::State("wrong passphrase, or the state file is damaged"))?,
        );
        let mut data_key = SecretPage::new(KEY_LEN)?;
        data_key.as_mut_slice().copy_from_slice(
            plaintext
                .get(..KEY_LEN)
                .ok_or(Error::Malformed("short data key"))?,
        );
        Ok(data_key)
    }

    /// Binds the wrapped key to the file format, slot kind and Argon2 inputs.
    fn aad(params: KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(8 + 2 + 12 + SALT_LEN);
        aad.extend_from_slice(STATE_MAGIC);
        aad.extend_from_slice(&[STATE_VERSION, SLOT_PASSPHRASE]);
        aad.extend_from_slice(&params.memory_kib.to_be_bytes());
        aad.extend_from_slice(&params.iterations.to_be_bytes());
        aad.extend_from_slice(&params.parallelism.to_be_bytes());
        aad.extend_from_slice(salt);
        aad
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.params.iterations.to_be_bytes());
        out.extend_from_slice(&self.params.parallelism.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }

    fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let slot = Self {
            params: KdfParams {
                memory_kib: r.u32()?,
                iterations: r.u32()?,
                parallelism: r.u32()?,
            },
            salt: r.take()?,
            nonce: r.take()?,
            wrapped: r.take()?,
        };
        r.finish()?;
        Ok(slot)
    }
}

/// The state file header: key slots.
struct Header {
    passphrase: PassphraseSlot,
    /// Slots of kinds this version doesn't understand, kept as (kind, body).
    unknown_slots: Vec<(u8, Vec<u8>)>,
}

impl Header {
    fn encode(&self) -> Result<Vec<u8>> {
        let count = u8::try_from(self.unknown_slots.len().saturating_add(1))
            .map_err(|_| Error::Malformed("too many key slots"))?;
        let mut out = Vec::new();
        out.extend_from_slice(STATE_MAGIC);
        out.push(STATE_VERSION);
        out.push(count);
        let mut passphrase_slot = Vec::with_capacity(PASSPHRASE_SLOT_LEN);
        self.passphrase.encode(&mut passphrase_slot);
        for (kind, body) in std::iter::once((SLOT_PASSPHRASE, &passphrase_slot))
            .chain(self.unknown_slots.iter().map(|(kind, body)| (*kind, body)))
        {
            let len =
                u16::try_from(body.len()).map_err(|_| Error::Malformed("key slot too long"))?;
            out.push(kind);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(body);
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
        let mut passphrase = None;
        let mut unknown_slots = Vec::new();
        for _ in 0..r.u8()? {
            let kind = r.u8()?;
            let len = usize::from(u16::from_be_bytes(r.take()?));
            let body = r.raw(len)?;
            match kind {
                SLOT_PASSPHRASE if passphrase.is_none() => {
                    passphrase = Some(PassphraseSlot::decode(body)?);
                }
                SLOT_PASSPHRASE => return Err(Error::Malformed("duplicate passphrase slot")),
                _ => unknown_slots.push((kind, body.to_vec())),
            }
        }
        let header = Self {
            passphrase: passphrase.ok_or(Error::Malformed("no passphrase slot"))?,
            unknown_slots,
        };
        Ok((header, file.len().saturating_sub(r.rest().len())))
    }
}

/// An unlocked vault directory. Holds the directory lock while it exists.
pub struct Vault {
    dir: PathBuf,
    data_key: SecretPage,
    header: Header,
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
            passphrase: PassphraseSlot::wrap(&data_key, passphrase, params)?,
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
            history_records: 0,
            _lock: lock,
        };
        vault.save(snapshot)?;
        Ok(vault)
    }

    /// Unlock the vault in `dir`. Returns it with the saved snapshot.
    ///
    /// # Errors
    /// Fails on a wrong passphrase, a damaged or unsupported file, or if another purple
    /// holds the directory.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let lock = lock_dir(dir)?;
        let file = Zeroizing::new(fs::read(dir.join(STATE_FILE))?);
        let (header, header_len) = Header::decode(&file)?;
        let (header_bytes, rest) = file
            .split_at_checked(header_len)
            .ok_or(Error::Malformed("state file too short"))?;
        let data_key = header.passphrase.unwrap(passphrase)?;
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

    /// Replace the passphrase. `old` must be the current one. Only the passphrase slot
    /// changes: the data key, and so the history, stay as they are. `snapshot` is saved
    /// with the new header.
    ///
    /// # Errors
    /// Fails if `old` is wrong, `new` is too short, or saving fails. The vault is unchanged
    /// on failure.
    pub fn change_passphrase(
        &mut self,
        old: &str,
        new: &str,
        params: KdfParams,
        snapshot: &[u8],
    ) -> Result<()> {
        check_passphrase(new)?;
        self.header.passphrase.unwrap(old)?;
        let slot = PassphraseSlot::wrap(&self.data_key, new, params)?;
        let previous = std::mem::replace(&mut self.header.passphrase, slot);
        if let Err(err) = self.save(snapshot) {
            self.header.passphrase = previous;
            return Err(err);
        }
        Ok(())
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

fn key_cipher(kek: &SecretPage) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(kek.as_slice())
        .map_err(|_| Error::Malformed("invalid key-encryption key"))
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

        let (_vault, snapshot) = Vault::open(&dir, "correct horse").unwrap();
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
        assert!(Vault::open(&dir, "wrong horse!").is_err());

        let path = dir.join(STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        // Any byte, header included, is authenticated.
        // Magic, version, slot count, slot kind and length, slot body.
        let header_len = 8 + 1 + 1 + 1 + 2 + PASSPHRASE_SLOT_LEN;
        for i in [0, 9, header_len - 1, header_len, bytes.len() - 1] {
            bytes[i] ^= 1;
            fs::write(&path, &bytes).unwrap();
            assert!(Vault::open(&dir, "correct horse").is_err(), "byte {i}");
            bytes[i] ^= 1;
        }
        fs::write(&path, &bytes).unwrap();
        assert!(Vault::open(&dir, "correct horse").is_ok());
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
        assert!(Vault::open(&dir, "correct horse").is_err());
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

        let (mut reopened, _) = Vault::open(&dir, "correct horse").unwrap();
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
            .change_passphrase("correct horse", "battery staple", FAST, b"state 2")
            .unwrap();
        drop(vault);

        assert_eq!(fs::read(dir.join(HISTORY_FILE)).unwrap(), history_before);
        assert!(Vault::open(&dir, "correct horse").is_err());
        let (reopened, snapshot) = Vault::open(&dir, "battery staple").unwrap();
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
                .change_passphrase("wrong horse!", "battery staple", FAST, b"x")
                .is_err()
        );
        assert!(
            vault
                .change_passphrase("correct horse", "short", FAST, b"x")
                .is_err()
        );
        vault.save(b"still works").unwrap();
        drop(vault);
        let (_vault, snapshot) = Vault::open(&dir, "correct horse").unwrap();
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
        let (reopened, snapshot) = Vault::open(&dir, "correct horse").unwrap();
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
        let err = Vault::open(&dir, "correct horse").unwrap_err();
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
}
