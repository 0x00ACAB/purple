//! On-disk storage: the encrypted state snapshot and the encrypted message history.
//!
//! A passphrase goes through Argon2id into a 32-byte master key, which lives in a
//! [`SecretPage`] (`memfd_secret` where available). HKDF splits it into a state key and a
//! history key.
//!
//! `state.purple`: header (magic, version, Argon2 parameters, salt), nonce, then the
//! snapshot sealed with XChaCha20-Poly1305 under the state key with the header as AAD.
//! Each save writes a temporary file, syncs it, and renames it over the old one, so a crash
//! leaves either the old state or the new one.
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
const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const STATE_HEADER_LEN: usize = 8 + 1 + 4 + 4 + 4 + SALT_LEN;
const HISTORY_HEADER_LEN: usize = 8 + 1;
/// Largest history record accepted when reading.
const MAX_RECORD_LEN: usize = 1 << 20;

/// Shortest passphrase accepted for a new vault, in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 8;

/// Argon2id cost parameters, stored in the state file so they can change later.
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

/// An unlocked vault directory. Holds the directory lock while it exists.
pub struct Vault {
    dir: PathBuf,
    master: SecretPage,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    history_records: u64,
    _lock: File,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("dir", &self.dir)
            .field("protection", &self.master.protection())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Whether `dir` already holds a vault.
    #[must_use]
    pub fn exists(dir: &Path) -> bool {
        dir.join(STATE_FILE).exists()
    }

    /// Create a new vault in `dir` and save `snapshot` as its first state. Any history left
    /// from an earlier vault is discarded, since it can't be decrypted anyway.
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
        if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(Error::State("passphrase must be at least 8 characters"));
        }
        let lock = lock_dir(dir)?;
        if Self::exists(dir) {
            return Err(Error::State("a vault already exists here"));
        }
        let mut salt = [0u8; SALT_LEN];
        fill_random(&mut salt)?;
        let master = derive_master(passphrase, &salt, params)?;
        let mut history = create_private(&dir.join(HISTORY_FILE))?;
        history.write_all(HISTORY_MAGIC)?;
        history.write_all(&[FORMAT_VERSION])?;
        history.sync_all()?;
        let vault = Self {
            dir: dir.to_owned(),
            master,
            params,
            salt,
            history_records: 0,
            _lock: lock,
        };
        vault.save(snapshot)?;
        Ok(vault)
    }

    /// Unlock the vault in `dir`. Returns it with the saved snapshot.
    ///
    /// # Errors
    /// Fails on a wrong passphrase, a damaged file, or if another purple holds the
    /// directory.
    pub fn open(dir: &Path, passphrase: &str) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let lock = lock_dir(dir)?;
        let file = Zeroizing::new(fs::read(dir.join(STATE_FILE))?);
        let (header, rest) = file
            .split_at_checked(STATE_HEADER_LEN)
            .ok_or(Error::Malformed("state file too short"))?;
        let mut r = Reader::new(header);
        if r.take::<8>()? != *STATE_MAGIC || r.u8()? != FORMAT_VERSION {
            return Err(Error::Malformed(
                "not a purple state file, or a newer version",
            ));
        }
        let params = KdfParams {
            memory_kib: r.u32()?,
            iterations: r.u32()?,
            parallelism: r.u32()?,
        };
        let salt = r.take::<SALT_LEN>()?;
        r.finish()?;

        let master = derive_master(passphrase, &salt, params)?;
        let (nonce, ciphertext) = rest
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(Error::Malformed("state file too short"))?;
        let snapshot = cipher(&master, b"purple state key")?
            .decrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| Error::State("wrong passphrase, or the state file is damaged"))?;

        let mut vault = Self {
            dir: dir.to_owned(),
            master,
            params,
            salt,
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

    /// How the master key is protected in memory.
    #[must_use]
    pub const fn protection(&self) -> Protection {
        self.master.protection()
    }

    /// Replace the saved state with `snapshot`, atomically.
    ///
    /// # Errors
    /// Fails if encryption or writing fails. The old state is untouched on failure.
    pub fn save(&self, snapshot: &[u8]) -> Result<()> {
        let header = self.state_header();
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce)?;
        let ciphertext = cipher(&self.master, b"purple state key")?
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
        let ciphertext = cipher(&self.master, b"purple history key")?
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
        if r.take::<8>()? != *HISTORY_MAGIC || r.u8()? != FORMAT_VERSION {
            return Err(Error::Malformed(
                "not a purple history file, or a newer version",
            ));
        }

        let cipher = cipher(&self.master, b"purple history key")?;
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

    fn state_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(STATE_HEADER_LEN);
        header.extend_from_slice(STATE_MAGIC);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&self.params.memory_kib.to_be_bytes());
        header.extend_from_slice(&self.params.iterations.to_be_bytes());
        header.extend_from_slice(&self.params.parallelism.to_be_bytes());
        header.extend_from_slice(&self.salt);
        header
    }
}

fn derive_master(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<SecretPage> {
    let params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Malformed("invalid Argon2 parameters"))?;
    let mut master = SecretPage::new(KEY_LEN)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, master.as_mut_slice())
        .map_err(|_| Error::Malformed("Argon2 failed"))?;
    Ok(master)
}

fn cipher(master: &SecretPage, label: &[u8]) -> Result<XChaCha20Poly1305> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, master.as_slice())
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
        for i in [0, STATE_HEADER_LEN - 1, bytes.len() - 1] {
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
