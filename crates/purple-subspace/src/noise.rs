//! Noise NK over a byte stream, for direct mode.
//!
//! The client knows the store's static key from its config, so nobody in between can pose
//! as the store. Each `write` becomes one or more Noise messages, each sent as a 2-byte
//! big-endian length and the ciphertext.

use std::io::{self, Read, Write};

use snow::{Builder, TransportState};

/// The handshake pattern and primitives.
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const MAX_MESSAGE: usize = 65_535;
const TAG_LEN: usize = 16;
const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;

/// A fresh static keypair: (private, public).
///
/// # Errors
/// Fails if the system random number generator does.
pub fn noise_keypair() -> io::Result<([u8; 32], [u8; 32])> {
    let pair = builder()?.generate_keypair().map_err(io::Error::other)?;
    Ok((key(&pair.private)?, key(&pair.public)?))
}

fn builder() -> io::Result<Builder<'static>> {
    Ok(Builder::new(
        NOISE_PATTERN.parse().map_err(io::Error::other)?,
    ))
}

fn key(bytes: &[u8]) -> io::Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| io::Error::other("key isn't 32 bytes"))
}

/// An encrypted, authenticated stream.
pub struct NoiseStream<S> {
    inner: S,
    state: TransportState,
    /// Decrypted bytes not yet read.
    pending: Vec<u8>,
    read_at: usize,
}

impl<S> std::fmt::Debug for NoiseStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseStream").finish_non_exhaustive()
    }
}

impl<S: Read + Write> NoiseStream<S> {
    /// Handshake as the client, checking the server holds the private half of
    /// `server_public`.
    ///
    /// # Errors
    /// Fails on an I/O error or a failed handshake.
    pub fn client(mut inner: S, server_public: &[u8; 32]) -> io::Result<Self> {
        let mut hs = builder()?
            .remote_public_key(server_public)
            .build_initiator()
            .map_err(io::Error::other)?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = hs.write_message(&[], &mut buf).map_err(io::Error::other)?;
        send(&mut inner, buf.get(..n).unwrap_or_default())?;
        let reply = recv(&mut inner)?;
        hs.read_message(&reply, &mut buf)
            .map_err(io::Error::other)?;
        Self::finish(inner, hs)
    }

    /// Handshake as the server with static key `private`.
    ///
    /// # Errors
    /// Fails on an I/O error or a failed handshake.
    pub fn server(mut inner: S, private: &[u8; 32]) -> io::Result<Self> {
        let mut hs = builder()?
            .local_private_key(private)
            .build_responder()
            .map_err(io::Error::other)?;
        let mut buf = vec![0u8; MAX_MESSAGE];
        let first = recv(&mut inner)?;
        hs.read_message(&first, &mut buf)
            .map_err(io::Error::other)?;
        let n = hs.write_message(&[], &mut buf).map_err(io::Error::other)?;
        send(&mut inner, buf.get(..n).unwrap_or_default())?;
        Self::finish(inner, hs)
    }

    fn finish(inner: S, hs: snow::HandshakeState) -> io::Result<Self> {
        Ok(Self {
            inner,
            state: hs.into_transport_mode().map_err(io::Error::other)?,
            pending: Vec::new(),
            read_at: 0,
        })
    }
}

impl<S: Read + Write> Read for NoiseStream<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.read_at >= self.pending.len() {
            let message = match recv(&mut self.inner) {
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                other => other?,
            };
            let mut plain = vec![0u8; message.len()];
            let n = self
                .state
                .read_message(&message, &mut plain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Noise message"))?;
            plain.truncate(n);
            self.pending = plain;
            self.read_at = 0;
        }
        let rest = self.pending.get(self.read_at..).unwrap_or_default();
        let n = rest.len().min(out.len());
        out.get_mut(..n)
            .unwrap_or_default()
            .copy_from_slice(rest.get(..n).unwrap_or_default());
        self.read_at = self.read_at.saturating_add(n);
        Ok(n)
    }
}

impl<S: Read + Write> Write for NoiseStream<S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let chunk = data
            .get(..data.len().min(MAX_PLAINTEXT))
            .unwrap_or_default();
        let mut message = vec![0u8; chunk.len().saturating_add(TAG_LEN)];
        let n = self
            .state
            .write_message(chunk, &mut message)
            .map_err(io::Error::other)?;
        send(&mut self.inner, message.get(..n).unwrap_or_default())?;
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn send(w: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let len =
        u16::try_from(message.len()).map_err(|_| io::Error::other("Noise message too long"))?;
    let mut framed = Vec::with_capacity(message.len().saturating_add(2));
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    w.write_all(&framed)
}

fn recv(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(len))];
    r.read_exact(&mut message)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn noise_round_trips_both_ways() {
        let (private, public) = noise_keypair().unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut s = NoiseStream::server(b, &private).unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&buf.map(|byte| byte.wrapping_add(1))).unwrap();
            s.flush().unwrap();
        });
        let mut c = NoiseStream::client(a, &public).unwrap();
        c.write_all(b"hello").unwrap();
        c.flush().unwrap();
        let mut back = [0u8; 5];
        c.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ifmmp");
        server.join().unwrap();
    }

    #[test]
    fn the_wrong_server_key_fails_the_handshake() {
        let (private, _) = noise_keypair().unwrap();
        let (_, other_public) = noise_keypair().unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || NoiseStream::server(b, &private).is_err());
        let client = NoiseStream::client(a, &other_public).and_then(|mut c| {
            c.write_all(b"x")?;
            c.flush()?;
            let mut one = [0u8; 1];
            c.read_exact(&mut one)
        });
        assert!(client.is_err() || server.join().unwrap());
    }

    #[test]
    fn large_writes_are_split_into_noise_messages() {
        let (private, public) = noise_keypair().unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let big = vec![7u8; 200_000];
        let expect = big.clone();
        let server = std::thread::spawn(move || {
            let mut s = NoiseStream::server(b, &private).unwrap();
            let mut got = vec![0u8; expect.len()];
            s.read_exact(&mut got).unwrap();
            assert_eq!(got, expect);
        });
        let mut c = NoiseStream::client(a, &public).unwrap();
        c.write_all(&big).unwrap();
        c.flush().unwrap();
        server.join().unwrap();
    }
}
