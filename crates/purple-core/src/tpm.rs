//! Sealing a secret in the TPM, so the vault can only be opened on this machine and wrong
//! passphrases are rate-limited by the TPM's dictionary-attack lockout.
//!
//! This speaks raw TPM 2.0 commands to `/dev/tpmrm0` (the kernel's resource manager), with
//! no tpm2-tss and no OpenSSL. Only five commands are needed: `CreatePrimary` for the
//! standard ECC P-256 storage key under the owner hierarchy, `Create` and `Load` for a
//! sealed keyed-hash object holding the secret, `Unseal`, and `FlushContext`. The storage
//! key is the same every time it's created, so nothing but the sealed object's public and
//! private parts needs storing.
//!
//! The object's password is sent in a plain password session, so it crosses the bus and the
//! kernel in the clear. Someone sniffing the bus of the running machine could learn it; a
//! stolen disk alone gives nothing.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use zeroize::Zeroizing;

use crate::session::{Error, Result};

/// The kernel's TPM resource manager, which flushes transient objects when the fd closes.
pub const TPM_DEVICE: &str = "/dev/tpmrm0";

/// Size of the sealed secret and of the object's password.
pub const SECRET_LEN: usize = 32;

/// Largest response the TPM sends to these commands, with room to spare.
const MAX_RESPONSE: usize = 4096;
/// Largest stored sealed object accepted.
const MAX_SEALED_LEN: usize = 1024;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0131;
const TPM_CC_CREATE: u32 = 0x0153;
const TPM_CC_LOAD: u32 = 0x0157;
const TPM_CC_UNSEAL: u32 = 0x015E;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0165;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RS_PW: u32 = 0x4000_0009;

const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ECC_NIST_P256: u16 = 0x0003;

const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const NO_DA: u32 = 1 << 10;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;

/// Format-one response codes carry the error in the low six bits.
const RC_FMT1: u32 = 0x080;
const RC_AUTH_FAIL: u32 = 0x00E;
const RC_BAD_AUTH: u32 = 0x022;
const RC_LOCKOUT: u32 = 0x921;

/// Keeps a secret and gives it back only for the right password, rate-limiting wrong ones.
/// The TPM in practice; tests use a fake.
pub trait Sealer {
    /// Seal `secret` under `auth`. Returns the sealed object to store.
    ///
    /// # Errors
    /// Fails if the TPM refuses or can't be reached.
    fn seal(&mut self, auth: &[u8; SECRET_LEN], secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>>;

    /// Give back the secret in `sealed`.
    ///
    /// # Errors
    /// Fails with a wrong `auth` (which counts toward the lockout), during a lockout, or if
    /// the TPM refuses or can't be reached.
    fn unseal(
        &mut self,
        sealed: &[u8],
        auth: &[u8; SECRET_LEN],
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>>;
}

/// A TPM reached through a device that takes one command per write and answers with one
/// response per read.
#[derive(Debug)]
pub struct Tpm<D> {
    device: D,
}

impl Tpm<File> {
    /// Open [`TPM_DEVICE`].
    ///
    /// # Errors
    /// Fails if the device is missing or this user may not use it.
    pub fn open() -> io::Result<Self> {
        Ok(Self::new(
            OpenOptions::new().read(true).write(true).open(TPM_DEVICE)?,
        ))
    }
}

impl<D: Read + Write> Tpm<D> {
    /// Talk to the TPM through `device`.
    pub const fn new(device: D) -> Self {
        Self { device }
    }

    /// Send one command and return the parameter area of the response.
    fn call(&mut self, command: &[u8], handles_out: usize) -> Result<(Vec<u32>, Vec<u8>)> {
        self.device.write_all(command)?;
        let mut response = vec![0u8; MAX_RESPONSE];
        let len = self.device.read(&mut response)?;
        response.truncate(len);
        parse_response(&response, handles_out)
    }

    fn create_primary(&mut self) -> Result<u32> {
        let mut params = Vec::new();
        // inSensitive: no password, no data.
        sized(&mut params, &[0, 0, 0, 0])?;
        sized(&mut params, &storage_key_template())?;
        params.extend_from_slice(&[0, 0]); // outsideInfo
        params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
        let command = command(TPM_CC_CREATE_PRIMARY, &[TPM_RH_OWNER], Some(&[]), &params)?;
        let (handles, _) = self.call(&command, 1)?;
        handles
            .first()
            .copied()
            .ok_or(Error::Malformed("TPM response without a handle"))
    }

    fn flush(&mut self, handle: u32) -> Result<()> {
        self.call(
            &command(TPM_CC_FLUSH_CONTEXT, &[], None, &handle.to_be_bytes())?,
            0,
        )?;
        Ok(())
    }

    /// Run `f` with the storage key loaded, flushing it after.
    fn with_primary<T>(&mut self, f: impl FnOnce(&mut Self, u32) -> Result<T>) -> Result<T> {
        let primary = self.create_primary()?;
        let result = f(self, primary);
        let flushed = self.flush(primary);
        let value = result?;
        flushed?;
        Ok(value)
    }
}

impl<D: Read + Write> Sealer for Tpm<D> {
    fn seal(&mut self, auth: &[u8; SECRET_LEN], secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>> {
        self.with_primary(|tpm, primary| {
            let mut sensitive = Zeroizing::new(Vec::new());
            sized(&mut sensitive, auth)?;
            sized(&mut sensitive, secret)?;
            let mut params = Zeroizing::new(Vec::new());
            sized(&mut params, &sensitive)?;
            sized(&mut params, &sealed_object_template())?;
            params.extend_from_slice(&[0, 0]); // outsideInfo
            params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
            let command = Zeroizing::new(command(TPM_CC_CREATE, &[primary], Some(&[]), &params)?);
            let (_, out) = tpm.call(&command, 0)?;
            // outPrivate then outPublic, both size-prefixed: store them as they came.
            let mut created = Params(&out);
            let private = created.sized()?;
            let public = created.sized()?;
            let mut sealed = Vec::new();
            sized(&mut sealed, public)?;
            sized(&mut sealed, private)?;
            Ok(sealed)
        })
    }

    fn unseal(
        &mut self,
        sealed: &[u8],
        auth: &[u8; SECRET_LEN],
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
        if sealed.len() > MAX_SEALED_LEN {
            return Err(Error::Malformed("sealed TPM object too long"));
        }
        let mut r = Params(sealed);
        let public = r.sized()?;
        let private = r.sized()?;
        r.finish()?;
        self.with_primary(|tpm, primary| {
            let mut params = Vec::new();
            sized(&mut params, private)?;
            sized(&mut params, public)?;
            let (handles, _) =
                tpm.call(&command(TPM_CC_LOAD, &[primary], Some(&[]), &params)?, 1)?;
            let object = *handles
                .first()
                .ok_or(Error::Malformed("TPM response without a handle"))?;
            let unsealed = tpm.call(&command(TPM_CC_UNSEAL, &[object], Some(auth), &[])?, 0);
            let flushed = tpm.flush(object);
            let (_, out) = unsealed?;
            flushed?;
            let out = Zeroizing::new(out);
            let mut unsealed_out = Params(&out);
            let data = unsealed_out.sized()?;
            let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
            if data.len() != SECRET_LEN {
                return Err(Error::Malformed("TPM returned a secret of the wrong size"));
            }
            secret.copy_from_slice(data);
            Ok(secret)
        })
    }
}

/// The TCG's standard storage key: ECC P-256, restricted decryption, AES-128-CFB. Being
/// standard, it's also the key other tools on this machine get.
fn storage_key_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    let attributes = FIXED_TPM
        | FIXED_PARENT
        | SENSITIVE_DATA_ORIGIN
        | USER_WITH_AUTH
        | NO_DA
        | RESTRICTED
        | DECRYPT;
    t.extend_from_slice(&attributes.to_be_bytes());
    t.extend_from_slice(&[0, 0]); // authPolicy
    for word in [
        TPM_ALG_AES,
        128,
        TPM_ALG_CFB,
        TPM_ALG_NULL,
        TPM_ECC_NIST_P256,
        TPM_ALG_NULL,
    ] {
        t.extend_from_slice(&word.to_be_bytes());
    }
    // unique: x and y, 32 zero bytes each.
    for _ in 0..2 {
        t.extend_from_slice(&32u16.to_be_bytes());
        t.extend_from_slice(&[0; 32]);
    }
    t
}

/// A sealed data object that needs its password to unseal. Without `noDA`, every wrong
/// password counts toward the TPM's lockout.
fn sealed_object_template() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
    t.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    t.extend_from_slice(&(FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH).to_be_bytes());
    t.extend_from_slice(&[0, 0]); // authPolicy
    t.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    t.extend_from_slice(&[0, 0]); // unique
    t
}

/// A command: header, handles, an optional password session, then `params`.
fn command(code: u32, handles: &[u32], password: Option<&[u8]>, params: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for handle in handles {
        body.extend_from_slice(&handle.to_be_bytes());
    }
    let tag = match password {
        Some(password) => {
            let mut session = Zeroizing::new(Vec::new());
            session.extend_from_slice(&TPM_RS_PW.to_be_bytes());
            session.extend_from_slice(&[0, 0]); // nonce
            session.push(0); // attributes
            sized(&mut session, password)?;
            let len = u32::try_from(session.len())
                .map_err(|_| Error::Malformed("TPM session too long"))?;
            body.extend_from_slice(&len.to_be_bytes());
            body.extend_from_slice(&session);
            TPM_ST_SESSIONS
        }
        None => TPM_ST_NO_SESSIONS,
    };
    body.extend_from_slice(params);
    let size = u32::try_from(body.len().saturating_add(10))
        .map_err(|_| Error::Malformed("TPM command too long"))?;
    let mut out = Vec::with_capacity(body.len().saturating_add(10));
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Check a response's code and split it into `handles` handles and the parameter area.
fn parse_response(response: &[u8], handles: usize) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut r = Params(response);
    let tag = r.u16()?;
    let size = r.u32()?;
    let code = r.u32()?;
    if usize::try_from(size).ok() != Some(response.len()) {
        return Err(Error::Malformed("TPM response has the wrong length"));
    }
    if code != 0 {
        return Err(response_error(code));
    }
    let mut out = Vec::with_capacity(handles);
    for _ in 0..handles {
        out.push(r.u32()?);
    }
    let params = match tag {
        TPM_ST_SESSIONS => {
            let len = usize::try_from(r.u32()?)
                .map_err(|_| Error::Malformed("TPM parameter area too long"))?;
            r.raw(len)?.to_vec()
        }
        TPM_ST_NO_SESSIONS => r.0.to_vec(),
        _ => return Err(Error::Malformed("unknown TPM response tag")),
    };
    Ok((out, params))
}

fn response_error(code: u32) -> Error {
    if code & RC_FMT1 != 0 && matches!(code & 0x3F, RC_AUTH_FAIL | RC_BAD_AUTH) {
        return Error::State("wrong passphrase");
    }
    if code == RC_LOCKOUT {
        return Error::State(
            "the TPM is refusing for now after too many wrong passphrases; try again later",
        );
    }
    Error::Io(io::Error::other(format!("TPM error {code:#x}")))
}

/// Append `data` with a big-endian u16 length in front: a TPM2B.
fn sized(out: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| Error::Malformed("TPM field too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// A cursor over TPM-marshalled bytes.
struct Params<'a>(&'a [u8]);

impl<'a> Params<'a> {
    fn raw(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(Error::Malformed("TPM data cut short"))?;
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self
            .raw(2)?
            .try_into()
            .map_err(|_| Error::Malformed("TPM data cut short"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self
            .raw(4)?
            .try_into()
            .map_err(|_| Error::Malformed("TPM data cut short"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn sized(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.raw(len)
    }

    const fn finish(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes after a TPM object"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// A device that records commands and answers with canned responses.
    #[derive(Default)]
    struct Canned {
        sent: Vec<Vec<u8>>,
        replies: VecDeque<Vec<u8>>,
    }

    impl Write for Canned {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.sent.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Canned {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let reply = self.replies.pop_front().unwrap();
            buf[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        }
    }

    fn reply(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(body.len().saturating_add(10))
                .unwrap()
                .to_be_bytes(),
        );
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// A success with `handle` and a parameter area holding `params`.
    fn ok_with(handle: Option<u32>, params: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some(handle) = handle {
            body.extend_from_slice(&handle.to_be_bytes());
        }
        body.extend_from_slice(&u32::try_from(params.len()).unwrap().to_be_bytes());
        body.extend_from_slice(params);
        body.extend_from_slice(&[0, 0, 0, 0, 0]); // auth response: nonce, attrs, hmac
        reply(TPM_ST_SESSIONS, 0, &body)
    }

    fn flushed() -> Vec<u8> {
        reply(TPM_ST_NO_SESSIONS, 0, &[])
    }

    fn tpm2b(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        sized(&mut out, data).unwrap();
        out
    }

    #[test]
    fn unseal_command_carries_the_password_in_a_password_session() {
        let auth = [7u8; SECRET_LEN];
        let got = command(TPM_CC_UNSEAL, &[0x8000_0001], Some(&auth), &[]).unwrap();
        let mut want = vec![
            0x80, 0x02, 0, 0, 0, 0x3B, 0, 0, 0x01, 0x5E, 0x80, 0, 0, 0x01,
        ];
        want.extend_from_slice(&[0, 0, 0, 0x29, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0x20]);
        want.extend_from_slice(&auth);
        assert_eq!(got, want);
    }

    #[test]
    fn storage_key_template_matches_the_tcg_srk_template() {
        let t = storage_key_template();
        assert_eq!(t.len(), 2 + 2 + 4 + 2 + 12 + 2 * (2 + 32));
        assert_eq!(&t[4..8], &0x0003_0472u32.to_be_bytes());
    }

    #[test]
    fn seal_then_unseal_against_canned_responses() {
        let public = b"public part".to_vec();
        let private = b"private part".to_vec();
        let secret = [9u8; SECRET_LEN];
        let mut device = Canned::default();
        let mut create_out = tpm2b(&private);
        create_out.extend_from_slice(&tpm2b(&public));
        create_out.extend_from_slice(&[0, 0, 0, 0]); // creation data and hash, abridged
        device.replies.extend([
            ok_with(Some(0x8000_0000), &[]),
            ok_with(None, &create_out),
            flushed(),
            ok_with(Some(0x8000_0000), &[]),
            ok_with(Some(0x8000_0001), &tpm2b(b"name")),
            ok_with(None, &tpm2b(&secret)),
            flushed(),
            flushed(),
        ]);
        let mut tpm = Tpm::new(device);
        let sealed = tpm.seal(&[1; SECRET_LEN], &secret).unwrap();
        let mut want = tpm2b(&public);
        want.extend_from_slice(&tpm2b(&private));
        assert_eq!(sealed, want);
        assert_eq!(*tpm.unseal(&sealed, &[1; SECRET_LEN]).unwrap(), secret);

        let codes: Vec<u32> = tpm
            .device
            .sent
            .iter()
            .map(|c| u32::from_be_bytes(c[6..10].try_into().unwrap()))
            .collect();
        assert_eq!(
            codes,
            [
                TPM_CC_CREATE_PRIMARY,
                TPM_CC_CREATE,
                TPM_CC_FLUSH_CONTEXT,
                TPM_CC_CREATE_PRIMARY,
                TPM_CC_LOAD,
                TPM_CC_UNSEAL,
                TPM_CC_FLUSH_CONTEXT,
                TPM_CC_FLUSH_CONTEXT
            ]
        );
        // Load gets the private part first, then the public part.
        let load = &tpm.device.sent[4];
        let mut params = tpm2b(&private);
        params.extend_from_slice(&tpm2b(&public));
        assert!(load.ends_with(&params));
    }

    #[test]
    fn a_wrong_password_flushes_the_object_and_says_so() {
        let mut device = Canned::default();
        device.replies.extend([
            ok_with(Some(0x8000_0000), &[]),
            ok_with(Some(0x8000_0001), &tpm2b(b"name")),
            // TPM_RC_AUTH_FAIL for session 1.
            reply(TPM_ST_NO_SESSIONS, 0x098E, &[]),
            flushed(),
            flushed(),
        ]);
        let mut tpm = Tpm::new(device);
        let mut sealed = tpm2b(b"public");
        sealed.extend_from_slice(&tpm2b(b"private"));
        let err = tpm.unseal(&sealed, &[0; SECRET_LEN]).unwrap_err();
        assert_eq!(err.to_string(), "wrong passphrase");
        assert_eq!(tpm.device.sent.len(), 5, "both handles flushed");
    }

    #[test]
    fn response_codes_map_to_errors() {
        assert_eq!(response_error(0x09A2).to_string(), "wrong passphrase");
        assert!(
            response_error(RC_LOCKOUT)
                .to_string()
                .contains("try again later")
        );
        assert_eq!(response_error(0x0101).to_string(), "TPM error 0x101");
    }

    #[test]
    fn responses_are_checked() {
        assert!(parse_response(&[0x80, 0x01, 0, 0, 0, 11, 0, 0, 0, 0], 0).is_err());
        assert!(parse_response(&[0x80, 0x01, 0, 0], 0).is_err());
        let mut sealed = tpm2b(b"public");
        sealed.extend_from_slice(&tpm2b(b"private"));
        sealed.push(0);
        let mut tpm = Tpm::new(Canned::default());
        assert!(tpm.unseal(&sealed, &[0; SECRET_LEN]).is_err());
    }

    /// Against this machine's TPM. One wrong password is tried, which adds one to the
    /// TPM's lockout counter; it decays on its own. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs access to /dev/tpmrm0"]
    fn real_tpm_seals_and_unseals() {
        let mut tpm = Tpm::open().unwrap();
        let secret = [0x5Au8; SECRET_LEN];
        let auth = [0xA5u8; SECRET_LEN];
        let sealed = tpm.seal(&auth, &secret).unwrap();
        assert_eq!(*tpm.unseal(&sealed, &auth).unwrap(), secret);
        let err = tpm.unseal(&sealed, &[0; SECRET_LEN]).unwrap_err();
        assert_eq!(err.to_string(), "wrong passphrase");
        // Sealing twice gives different objects; both stay usable.
        let again = tpm.seal(&auth, &secret).unwrap();
        assert_ne!(again, sealed);
        assert_eq!(*tpm.unseal(&again, &auth).unwrap(), secret);
    }
}
