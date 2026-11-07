//! A SOCKS5 client for tor's Unix SOCKS socket. The username is the isolation key: with
//! `IsolateSOCKSAuth`, tor gives each distinct username its own circuit.

use std::fmt::Write as _;
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;

use hkdf::Hkdf;
use purple_combadge::StreamSeed;
use sha2::Sha256;

/// Isolation key for cover traffic before any stream has a circuit.
pub const COVER_ISOLATION: &str = "cover";

/// The isolation key for `stream`: unlinkable to the seed, the same every time.
#[must_use]
pub fn isolation_key(stream: &StreamSeed) -> String {
    let mut key = [0u8; 16];
    // 16 bytes is within HKDF-SHA256's limit, so this can't fail.
    Hkdf::<Sha256>::new(Some(b"purple tor isolation v1"), &stream.0)
        .expand(&[], &mut key)
        .ok();
    key.iter().fold(String::new(), |mut out, b| {
        // Writing to a String can't fail.
        write!(out, "{b:02x}").ok();
        out
    })
}

/// Open a stream to `host:port` through `s`, a fresh connection to tor's SOCKS socket, on
/// the circuit for `isolation`. The caller sets its timeouts.
///
/// # Errors
/// Fails if tor refuses or can't reach the host; onion-service failures say which step.
pub fn socks_connect(
    mut s: UnixStream,
    isolation: &str,
    host: &str,
    port: u16,
) -> io::Result<UnixStream> {
    s.write_all(&[5, 1, 2])?;
    let mut choice = [0u8; 2];
    s.read_exact(&mut choice)?;
    if choice != [5, 2] {
        return Err(io::Error::other("tor's SOCKS port refused username auth"));
    }
    let user =
        u8::try_from(isolation.len()).map_err(|_| io::Error::other("isolation key too long"))?;
    let mut auth = vec![1, user];
    auth.extend_from_slice(isolation.as_bytes());
    auth.extend_from_slice(&[1, b'x']);
    s.write_all(&auth)?;
    let mut ok = [0u8; 2];
    s.read_exact(&mut ok)?;
    if ok != [1, 0] {
        return Err(io::Error::other(
            "tor's SOCKS port rejected the isolation key",
        ));
    }
    let len = u8::try_from(host.len()).map_err(|_| io::Error::other("host name too long"))?;
    let mut req = vec![5, 1, 0, 3, len];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut reply = [0u8; 4];
    s.read_exact(&mut reply)?;
    let [5, rep, _, atyp] = reply else {
        return Err(io::Error::other("malformed SOCKS reply"));
    };
    let rest = match atyp {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            let [n] = n;
            usize::from(n)
        }
        _ => return Err(io::Error::other("malformed SOCKS reply")),
    };
    let mut skip = vec![0u8; rest.saturating_add(2)];
    s.read_exact(&mut skip)?;
    if rep != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            socks_error(rep),
        ));
    }
    Ok(s)
}

/// tor's SOCKS reply codes, including its onion-service extensions (0xF0 to 0xF7).
fn socks_error(rep: u8) -> String {
    let why = match rep {
        1 => "general failure",
        2 => "not allowed",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        0xF0 => "onion service descriptor not found",
        0xF1 => "onion service descriptor is invalid",
        0xF2 => "onion service introduction failed",
        0xF3 => "onion service rendezvous failed",
        0xF6 => "bad onion address",
        0xF7 => "onion service introduction timed out",
        _ => "unknown error",
    };
    format!("tor couldn't connect: {why}")
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    use purple_combadge::{SEED_LEN, StreamSeed};

    use super::*;

    fn socket(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("purple-socks-{name}-{}", std::process::id()));
        std::fs::remove_file(&p).ok();
        p
    }

    /// A SOCKS5 server that checks the handshake and answers with `rep`, then echoes.
    fn fake_tor(path: &Path, rep: u8) -> std::thread::JoinHandle<(String, String, u16)> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            c.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [5, 1, 2], "offers username/password only");
            c.write_all(&[5, 2]).unwrap();
            let mut head = [0u8; 2];
            c.read_exact(&mut head).unwrap();
            let mut user = vec![0u8; usize::from(head[1])];
            c.read_exact(&mut user).unwrap();
            let mut plen = [0u8; 1];
            c.read_exact(&mut plen).unwrap();
            let mut pass = vec![0u8; usize::from(plen[0])];
            c.read_exact(&mut pass).unwrap();
            c.write_all(&[1, 0]).unwrap();
            let mut req = [0u8; 5];
            c.read_exact(&mut req).unwrap();
            assert_eq!(&req[..4], &[5, 1, 0, 3], "CONNECT by domain name");
            let mut host = vec![0u8; usize::from(req[4])];
            c.read_exact(&mut host).unwrap();
            let mut port = [0u8; 2];
            c.read_exact(&mut port).unwrap();
            c.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            if rep == 0 {
                let mut b = [0u8; 4];
                c.read_exact(&mut b).unwrap();
                c.write_all(&b).unwrap();
            }
            (
                String::from_utf8(user).unwrap(),
                String::from_utf8(host).unwrap(),
                u16::from_be_bytes(port),
            )
        })
    }

    #[test]
    fn connects_with_the_isolation_key_as_username() {
        let path = socket("ok");
        let server = fake_tor(&path, 0);
        let mut s = socks_connect(
            UnixStream::connect(&path).unwrap(),
            "abcd",
            "example.onion",
            80,
        )
        .unwrap();
        s.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        assert_eq!(
            server.join().unwrap(),
            ("abcd".into(), "example.onion".into(), 80)
        );
    }

    #[test]
    fn onion_errors_are_reported() {
        let path = socket("err");
        let server = fake_tor(&path, 0xF2);
        let err = socks_connect(
            UnixStream::connect(&path).unwrap(),
            "k",
            "example.onion",
            80,
        )
        .unwrap_err();
        assert!(err.to_string().contains("introduction failed"), "{err}");
        server.join().unwrap();
    }

    #[test]
    fn isolation_keys_differ_per_stream_and_hide_the_seed() {
        let a = isolation_key(&StreamSeed([1; SEED_LEN]));
        let b = isolation_key(&StreamSeed([2; SEED_LEN]));
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(!a.contains("0101"));
        assert_ne!(a, COVER_ISOLATION);
    }
}
