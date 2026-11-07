//! Sealing a secret in the TPM, so the vault can only be opened on this machine and wrong
//! passphrases are rate-limited by the TPM's dictionary-attack lockout.
//!
//! This speaks raw TPM 2.0 commands to `/dev/tpmrm0` (the kernel's resource manager), with
//! no tpm2-tss and no OpenSSL. `CreatePrimary` makes the standard ECC P-256 storage key
//! under the owner hierarchy; `Create` and `Load` make and load a sealed keyed-hash object
//! holding the secret; `Unseal` gives it back; `StartAuthSession` and `FlushContext` manage
//! the session. The storage key is the same every time it's created, so nothing but the
//! sealed object's public and private parts needs storing.
//!
//! Everything after `CreatePrimary` runs in a salted HMAC session: the salt is sent
//! encrypted to the storage key (ECDH), so only this process and the TPM know the session
//! key. The object's password then never crosses the bus; it only keys HMACs. `Create`'s
//! sensitive data (password and secret) and `Unseal`'s answer are encrypted with the
//! session's XOR stream, and every response's HMAC is checked. What's left is an active
//! attacker on the bus posing as the TPM, who could hand back a storage key of their own.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, PublicKey, SecretKey};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
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
/// Size of SHA-256 digests, and so of nonces, session keys and HMACs here.
const DIGEST_LEN: usize = 32;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0131;
const TPM_CC_CREATE: u32 = 0x0153;
const TPM_CC_LOAD: u32 = 0x0157;
const TPM_CC_UNSEAL: u32 = 0x015E;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0165;
const TPM_CC_START_AUTH_SESSION: u32 = 0x0176;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_SE_HMAC: u8 = 0x00;

const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_XOR: u16 = 0x000A;
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

/// Session attributes: keep the session open, encrypt the command's first parameter, and
/// have the TPM encrypt the response's first parameter.
const CONTINUE_SESSION: u8 = 0x01;
const DECRYPT_PARAM: u8 = 0x20;
const ENCRYPT_PARAM: u8 = 0x40;

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

/// The storage key, loaded.
struct Primary {
    handle: u32,
    /// Its TPM name: the name algorithm, then the hash of its public area.
    name: Vec<u8>,
    public: PublicKey,
}

/// One command for [`Tpm::call_hmac`].
struct Request<'a> {
    code: u32,
    /// Each handle with its name.
    handles: &'a [(u32, &'a [u8])],
    /// The password of the entity being used.
    auth: &'a [u8],
    params: &'a [u8],
    attributes: u8,
    /// How many handles the response carries.
    handles_out: usize,
}

/// An open salted HMAC session.
struct Session {
    handle: u32,
    key: Zeroizing<Vec<u8>>,
    /// The TPM's latest nonce.
    nonce_tpm: Vec<u8>,
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

    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.device.write_all(command)?;
        let mut response = vec![0u8; MAX_RESPONSE];
        let len = self.device.read(&mut response)?;
        response.truncate(len);
        Ok(response)
    }

    /// Send one command without an HMAC session and return the response's handles and
    /// parameter area.
    fn call(&mut self, command: &[u8], handles_out: usize) -> Result<(Vec<u32>, Vec<u8>)> {
        let response = self.exchange(command)?;
        let (handles, params, _) = parse_response(&response, handles_out)?;
        Ok((handles, params.to_vec()))
    }

    fn create_primary(&mut self) -> Result<Primary> {
        let mut params = Vec::new();
        // inSensitive: no password, no data.
        sized(&mut params, &[0, 0, 0, 0])?;
        sized(&mut params, &storage_key_template())?;
        params.extend_from_slice(&[0, 0]); // outsideInfo
        params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
        let command = command(TPM_CC_CREATE_PRIMARY, &[TPM_RH_OWNER], Some(&[]), &params)?;
        let (handles, out) = self.call(&command, 1)?;
        let handle = *handles
            .first()
            .ok_or(Error::Malformed("TPM response without a handle"))?;
        let public_area = Params(&out).sized()?;
        Ok(Primary {
            handle,
            name: name_of(public_area),
            public: storage_key_point(public_area)?,
        })
    }

    /// Start a salted HMAC session, the salt encrypted to `primary` by ECDH.
    fn start_session(&mut self, primary: &Primary) -> Result<Session> {
        let ephemeral = loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            fill_random(bytes.as_mut_slice())?;
            if let Ok(key) = SecretKey::from_slice(bytes.as_slice()) {
                break key;
            }
        };
        let shared =
            p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), primary.public.as_affine());
        let ours = ephemeral.public_key().to_encoded_point(false);
        let theirs = primary.public.to_encoded_point(false);
        let (Some(our_x), Some(our_y), Some(their_x)) = (ours.x(), ours.y(), theirs.x()) else {
            return Err(Error::Malformed("ECC point at infinity"));
        };
        let salt = kdfe(shared.raw_secret_bytes(), b"SECRET", our_x, their_x);

        let mut nonce_caller = [0u8; DIGEST_LEN];
        fill_random(&mut nonce_caller)?;
        let mut point = Vec::new();
        sized(&mut point, our_x)?;
        sized(&mut point, our_y)?;
        let mut params = Vec::new();
        sized(&mut params, &nonce_caller)?;
        sized(&mut params, &point)?;
        params.push(TPM_SE_HMAC);
        params.extend_from_slice(&TPM_ALG_XOR.to_be_bytes());
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // the XOR stream's hash
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes()); // authHash
        let (handles, out) = self.call(
            &command(
                TPM_CC_START_AUTH_SESSION,
                &[primary.handle, TPM_RH_NULL],
                None,
                &params,
            )?,
            1,
        )?;
        let handle = *handles
            .first()
            .ok_or(Error::Malformed("TPM response without a handle"))?;
        let nonce_tpm = Params(&out).sized()?.to_vec();
        // Unbound, so the session key comes from the salt alone.
        let key = kdfa(&salt, b"ATH", &nonce_tpm, &nonce_caller, DIGEST_LEN)?;
        Ok(Session {
            handle,
            key,
            nonce_tpm,
        })
    }

    /// Send one command authorized through `session`. With `DECRYPT_PARAM` in the
    /// request's attributes, the first parameter (a TPM2B) is encrypted on the way; with
    /// `ENCRYPT_PARAM`, the TPM encrypts the response's first parameter and this decrypts
    /// it. The response's HMAC is checked before anything in it is used.
    fn call_hmac(
        &mut self,
        session: &mut Session,
        request: &Request<'_>,
    ) -> Result<(Vec<u32>, Zeroizing<Vec<u8>>)> {
        let Request {
            code,
            handles,
            auth,
            params,
            attributes,
            handles_out,
        } = *request;
        let mut nonce_caller = [0u8; DIGEST_LEN];
        fill_random(&mut nonce_caller)?;
        let mut key = Zeroizing::new(session.key.to_vec());
        key.extend_from_slice(trim_zeros(auth));

        let mut params = Zeroizing::new(params.to_vec());
        if attributes & DECRYPT_PARAM != 0 {
            xor_first_param(&mut params, &key, &nonce_caller, &session.nonce_tpm)?;
        }
        let mut cp_hash = Sha256::new();
        cp_hash.update(code.to_be_bytes());
        for (_, name) in handles {
            cp_hash.update(name);
        }
        cp_hash.update(params.as_slice());
        let hmac = session_hmac(
            &key,
            &cp_hash.finalize(),
            &nonce_caller,
            &session.nonce_tpm,
            attributes,
        )?;

        let mut body = Zeroizing::new(Vec::new());
        for (handle, _) in handles {
            body.extend_from_slice(&handle.to_be_bytes());
        }
        let mut area = Vec::new();
        area.extend_from_slice(&session.handle.to_be_bytes());
        sized(&mut area, &nonce_caller)?;
        area.push(attributes);
        sized(&mut area, &hmac)?;
        let area_len =
            u32::try_from(area.len()).map_err(|_| Error::Malformed("TPM session too long"))?;
        body.extend_from_slice(&area_len.to_be_bytes());
        body.extend_from_slice(&area);
        body.extend_from_slice(&params);
        let command = Zeroizing::new(frame(TPM_ST_SESSIONS, code, &body)?);

        let response = Zeroizing::new(self.exchange(&command)?);
        let (out_handles, out_params, auth_area) = parse_response(&response, handles_out)?;
        let mut r = Params(auth_area);
        let nonce_tpm = r.sized()?.to_vec();
        let response_attributes = r.u8()?;
        let response_hmac = r.sized()?;
        r.finish()?;
        let mut rp_hash = Sha256::new();
        rp_hash.update(0u32.to_be_bytes());
        rp_hash.update(code.to_be_bytes());
        rp_hash.update(out_params);
        let mut mac = hmac_sha256(&key)?;
        mac.update(&rp_hash.finalize());
        mac.update(&nonce_tpm);
        mac.update(&nonce_caller);
        mac.update(&[response_attributes]);
        mac.verify_slice(response_hmac)
            .map_err(|_| Error::Malformed("the TPM's response failed its HMAC check"))?;
        session.nonce_tpm = nonce_tpm;

        let mut out = Zeroizing::new(out_params.to_vec());
        if attributes & ENCRYPT_PARAM != 0 {
            xor_first_param(&mut out, &key, &session.nonce_tpm, &nonce_caller)?;
        }
        Ok((out_handles, out))
    }

    fn flush(&mut self, handle: u32) -> Result<()> {
        self.call(
            &command(TPM_CC_FLUSH_CONTEXT, &[], None, &handle.to_be_bytes())?,
            0,
        )?;
        Ok(())
    }

    /// Run `f` with the storage key loaded and a session open, flushing both after.
    fn with_session<T>(
        &mut self,
        f: impl FnOnce(&mut Self, &Primary, &mut Session) -> Result<T>,
    ) -> Result<T> {
        let primary = self.create_primary()?;
        let result = self.start_session(&primary).and_then(|mut session| {
            let result = f(self, &primary, &mut session);
            // An auth failure can already have closed the session; that's fine.
            self.flush(session.handle).ok();
            result
        });
        let flushed = self.flush(primary.handle);
        let value = result?;
        flushed?;
        Ok(value)
    }
}

impl<D: Read + Write> Sealer for Tpm<D> {
    fn seal(&mut self, auth: &[u8; SECRET_LEN], secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>> {
        self.with_session(|tpm, primary, session| {
            let mut sensitive = Zeroizing::new(Vec::new());
            sized(&mut sensitive, auth)?;
            sized(&mut sensitive, secret)?;
            let mut params = Zeroizing::new(Vec::new());
            sized(&mut params, &sensitive)?;
            sized(&mut params, &sealed_object_template())?;
            params.extend_from_slice(&[0, 0]); // outsideInfo
            params.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
            let (_, out) = tpm.call_hmac(
                session,
                &Request {
                    code: TPM_CC_CREATE,
                    handles: &[(primary.handle, &primary.name)],
                    auth: &[],
                    params: &params,
                    attributes: CONTINUE_SESSION | DECRYPT_PARAM,
                    handles_out: 0,
                },
            )?;
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
        let object_name = name_of(public);
        self.with_session(|tpm, primary, session| {
            let mut params = Vec::new();
            sized(&mut params, private)?;
            sized(&mut params, public)?;
            let (handles, _) = tpm.call_hmac(
                session,
                &Request {
                    code: TPM_CC_LOAD,
                    handles: &[(primary.handle, &primary.name)],
                    auth: &[],
                    params: &params,
                    attributes: CONTINUE_SESSION,
                    handles_out: 1,
                },
            )?;
            let object = *handles
                .first()
                .ok_or(Error::Malformed("TPM response without a handle"))?;
            let unsealed = tpm.call_hmac(
                session,
                &Request {
                    code: TPM_CC_UNSEAL,
                    handles: &[(object, &object_name)],
                    auth,
                    params: &[],
                    attributes: CONTINUE_SESSION | ENCRYPT_PARAM,
                    handles_out: 0,
                },
            );
            let flushed = tpm.flush(object);
            let (_, out) = unsealed?;
            flushed?;
            let data = Params(&out).sized()?;
            if data.len() != SECRET_LEN {
                return Err(Error::Malformed("TPM returned a secret of the wrong size"));
            }
            let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
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

/// The storage key's public point, from its public area. The template's fields come
/// back as they were sent, followed by the point.
fn storage_key_point(public_area: &[u8]) -> Result<PublicKey> {
    let template = storage_key_template();
    // Everything before `unique` must match what was asked for.
    let fixed = template.len().saturating_sub(2 * (2 + 32));
    let mut r = Params(public_area);
    if r.raw(fixed)? != template.get(..fixed).unwrap_or_default() {
        return Err(Error::Malformed(
            "the TPM's storage key isn't the one asked for",
        ));
    }
    let x = r.sized()?;
    let y = r.sized()?;
    r.finish()?;
    let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
        return Err(Error::Malformed(
            "storage key coordinates have the wrong size",
        ));
    };
    let point = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&point))
        .and_then(|point| PublicKey::from_affine(point).ok())
        .ok_or(Error::Malformed("the TPM's storage key isn't on P-256"))
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

/// An object's TPM name: SHA-256's algorithm ID, then the hash of its public area.
fn name_of(public_area: &[u8]) -> Vec<u8> {
    let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
    name.extend_from_slice(&Sha256::digest(public_area));
    name
}

/// A command with an optional password session, then `params`.
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
    frame(tag, code, &body)
}

/// The command header in front of `body`.
fn frame(tag: u16, code: u32, body: &[u8]) -> Result<Vec<u8>> {
    let size = u32::try_from(body.len().saturating_add(10))
        .map_err(|_| Error::Malformed("TPM command too long"))?;
    let mut out = Vec::with_capacity(body.len().saturating_add(10));
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Check a response's code and split it into `handles` handles, the parameter area and
/// the session area (empty without sessions).
fn parse_response(response: &[u8], handles: usize) -> Result<(Vec<u32>, &[u8], &[u8])> {
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
    match tag {
        TPM_ST_SESSIONS => {
            let len = usize::try_from(r.u32()?)
                .map_err(|_| Error::Malformed("TPM parameter area too long"))?;
            let params = r.raw(len)?;
            Ok((out, params, r.0))
        }
        TPM_ST_NO_SESSIONS => Ok((out, r.0, &[])),
        _ => Err(Error::Malformed("unknown TPM response tag")),
    }
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

fn hmac_sha256(key: &[u8]) -> Result<Hmac<Sha256>> {
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::Malformed("invalid HMAC key"))
}

/// A command's authorization HMAC: over the parameter hash, both nonces and the
/// attributes.
fn session_hmac(
    key: &[u8],
    cp_hash: &[u8],
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    attributes: u8,
) -> Result<Vec<u8>> {
    let mut mac = hmac_sha256(key)?;
    mac.update(cp_hash);
    mac.update(nonce_caller);
    mac.update(nonce_tpm);
    mac.update(&[attributes]);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// XOR the contents of the TPM2B at the start of `params` with the session's stream:
/// `KDFa` over `key`, with `newer` the nonce of whoever sends it.
fn xor_first_param(params: &mut [u8], key: &[u8], newer: &[u8], older: &[u8]) -> Result<()> {
    let (len, rest) = params
        .split_first_chunk_mut::<2>()
        .ok_or(Error::Malformed("TPM parameter cut short"))?;
    let data = rest
        .get_mut(..usize::from(u16::from_be_bytes(*len)))
        .ok_or(Error::Malformed("TPM parameter cut short"))?;
    let mask = kdfa(key, b"XOR", newer, older, data.len())?;
    for (byte, m) in data.iter_mut().zip(mask.iter()) {
        *byte ^= m;
    }
    Ok(())
}

/// The TPM's `KDFa` with HMAC-SHA256 (counter mode, SP 800-108), for `len` bytes.
fn kdfa(
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let bits = u32::try_from(len.saturating_mul(8))
        .map_err(|_| Error::Malformed("KDFa output too long"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(len.saturating_add(DIGEST_LEN)));
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut mac = hmac_sha256(key)?;
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0]);
        mac.update(context_u);
        mac.update(context_v);
        mac.update(&bits.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter = counter
            .checked_add(1)
            .ok_or(Error::Malformed("KDFa output too long"))?;
    }
    out.truncate(len);
    Ok(out)
}

/// The TPM's `KDFe` with SHA-256 (SP 800-56A), for one digest's worth: how an ECDH salt
/// becomes the session salt.
fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(z);
    hash.update(label);
    hash.update([0]);
    hash.update(party_u);
    hash.update(party_v);
    Zeroizing::new(hash.finalize().to_vec())
}

/// An authValue as the TPM uses it in HMAC keys: without trailing zero bytes.
fn trim_zeros(auth: &[u8]) -> &[u8] {
    let end = auth
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    auth.get(..end).unwrap_or_default()
}

fn fill_random(out: &mut [u8]) -> Result<()> {
    OsRng
        .try_fill_bytes(out)
        .map_err(|_| Error::Malformed("OS random number generator failed"))
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

    fn u8(&mut self) -> Result<u8> {
        self.raw(1)?
            .first()
            .copied()
            .ok_or(Error::Malformed("TPM data cut short"))
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
    use super::*;

    fn tpm2b(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        sized(&mut out, data).unwrap();
        out
    }

    #[test]
    fn password_session_commands_are_laid_out_as_the_spec_says() {
        let got = command(TPM_CC_CREATE_PRIMARY, &[TPM_RH_OWNER], Some(&[]), &[0xAB]).unwrap();
        let mut want = vec![
            0x80, 0x02, 0, 0, 0, 0x1C, 0, 0, 0x01, 0x31, 0x40, 0, 0, 0x01,
        ];
        want.extend_from_slice(&[0, 0, 0, 0x09, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, 0xAB]);
        assert_eq!(got, want);
    }

    #[test]
    fn storage_key_template_matches_the_tcg_srk_template() {
        let t = storage_key_template();
        assert_eq!(t.len(), 2 + 2 + 4 + 2 + 12 + 2 * (2 + 32));
        assert_eq!(&t[4..8], &0x0003_0472u32.to_be_bytes());
    }

    #[test]
    fn storage_key_points_are_checked() {
        let key = SecretKey::from_slice(&[7; 32]).unwrap().public_key();
        let point = key.to_encoded_point(false);
        let template = storage_key_template();
        let fixed = &template[..template.len() - 68];
        let area = [
            fixed,
            &tpm2b(point.x().unwrap()),
            &tpm2b(point.y().unwrap()),
        ]
        .concat();
        assert_eq!(storage_key_point(&area).unwrap(), key);

        let mut off_curve = area.clone();
        *off_curve.last_mut().unwrap() ^= 1;
        assert!(storage_key_point(&off_curve).is_err());
        let mut other_template = area;
        other_template[0] ^= 1;
        assert!(storage_key_point(&other_template).is_err());
    }

    #[test]
    fn kdfa_gives_the_requested_length_and_depends_on_every_input() {
        let base = kdfa(b"key", b"XOR", b"u", b"v", 70).unwrap();
        assert_eq!(base.len(), 70);
        assert_eq!(*kdfa(b"key", b"XOR", b"u", b"v", 70).unwrap(), *base);
        // The requested length is an input too, so a shorter stream isn't a prefix.
        assert_ne!(
            kdfa(b"key", b"XOR", b"u", b"v", 32).unwrap()[..],
            base[..32]
        );
        for other in [
            kdfa(b"kez", b"XOR", b"u", b"v", 70).unwrap(),
            kdfa(b"key", b"ATH", b"u", b"v", 70).unwrap(),
            kdfa(b"key", b"XOR", b"v", b"u", 70).unwrap(),
        ] {
            assert_ne!(*other, *base);
        }
    }

    #[test]
    fn parameter_encryption_round_trips_and_leaves_the_size_alone() {
        let mut params = [tpm2b(b"secret secret"), vec![1, 2, 3]].concat();
        let original = params.clone();
        xor_first_param(&mut params, b"key", b"newer", b"older").unwrap();
        assert_eq!(params[..2], original[..2]);
        assert_ne!(params[2..15], original[2..15]);
        assert_eq!(
            params[15..],
            original[15..],
            "later parameters stay as they are"
        );
        xor_first_param(&mut params, b"key", b"newer", b"older").unwrap();
        assert_eq!(params, original);
    }

    #[test]
    fn trailing_zeros_are_trimmed_from_auth_values() {
        assert_eq!(trim_zeros(&[1, 0, 2, 0, 0]), [1, 0, 2]);
        assert!(trim_zeros(&[0, 0]).is_empty());
        assert!(trim_zeros(&[]).is_empty());
    }

    #[test]
    fn response_codes_map_to_errors() {
        assert_eq!(response_error(0x098E).to_string(), "wrong passphrase");
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
        let (_, params, sessions) =
            parse_response(&[0x80, 0x02, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 1, 9, 8], 0).unwrap();
        assert_eq!((params, sessions), (&[9u8][..], &[8u8][..]));
    }

    /// Records everything that crosses the device, both ways.
    struct Recording<D> {
        device: D,
        transcript: Vec<u8>,
    }

    impl<D: Read> Read for Recording<D> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = self.device.read(buf)?;
            self.transcript.extend_from_slice(&buf[..len]);
            Ok(len)
        }
    }

    impl<D: Write> Write for Recording<D> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let len = self.device.write(buf)?;
            self.transcript.extend_from_slice(&buf[..len]);
            Ok(len)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.device.flush()
        }
    }

    fn real_tpm() -> Tpm<Recording<File>> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TPM_DEVICE)
            .unwrap();
        Tpm::new(Recording {
            device,
            transcript: Vec::new(),
        })
    }

    fn random_pair() -> ([u8; SECRET_LEN], [u8; SECRET_LEN]) {
        let mut auth = [0u8; SECRET_LEN];
        let mut secret = [0u8; SECRET_LEN];
        fill_random(&mut auth).unwrap();
        fill_random(&mut secret).unwrap();
        // A trailing zero, which the TPM trims from HMAC keys.
        auth[SECRET_LEN - 1] = 0;
        (auth, secret)
    }

    fn assert_off_the_bus(transcript: &[u8], auth: &[u8], secret: &[u8]) {
        for (what, needle) in [("password", &auth[..16]), ("secret", &secret[..16])] {
            assert!(
                !transcript.windows(needle.len()).any(|w| w == needle),
                "the {what} crossed the bus"
            );
        }
    }

    /// Against this machine's TPM: sealing sends both the password and the secret, and
    /// neither may appear on the bus. Sealing uses only the storage key, which isn't under
    /// lockout. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs access to /dev/tpmrm0"]
    fn real_tpm_seals_without_either_secret_on_the_bus() {
        let mut tpm = real_tpm();
        let (auth, secret) = random_pair();
        let sealed = tpm.seal(&auth, &secret).unwrap();
        let again = tpm.seal(&auth, &secret).unwrap();
        assert_ne!(again, sealed);
        assert_off_the_bus(&tpm.device.transcript, &auth, &secret);
    }

    /// Against this machine's TPM, which must not be locked out. No wrong password is
    /// tried: some TPMs lock out after three. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "needs access to /dev/tpmrm0, not locked out"]
    fn real_tpm_unseals_without_either_secret_on_the_bus() {
        let mut tpm = real_tpm();
        let (auth, secret) = random_pair();
        let sealed = tpm.seal(&auth, &secret).unwrap();
        assert_eq!(*tpm.unseal(&sealed, &auth).unwrap(), secret);
        assert_eq!(*tpm.unseal(&sealed, &auth).unwrap(), secret);
        assert_off_the_bus(&tpm.device.transcript, &auth, &secret);
    }
}
