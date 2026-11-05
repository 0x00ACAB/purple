//! purple-store: serves boxes to purple clients. tor on the same machine publishes
//! `--onion-socket` as an onion service; `--direct` also listens for Noise connections
//! from clients that can't reach Tor.
//!
//! Usage: `purple-store --data <dir> --onion-socket <path> [--direct <ip:port>]
//! [--max-gb <n>]`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use purple_harden::sandbox::{Network, Policy, restrict};
use purple_net::noise::{NoiseStream, noise_keypair};
use purple_net::serve_provider;
use purple_store::disk::{DEFAULT_LIMITS, DiskStore, Limits, SharedStore};

const USAGE: &str = "usage: purple-store --data <dir> --onion-socket <path> \
                     [--direct <ip:port>] [--max-gb <n>]";
/// Each connection may write this many boxes a second; purple clients write 2.
const WRITES_PER_SEC: u32 = 10;
const KEY_FILE: &str = "noise.key";
/// A connection that sends nothing for this long is closed; the client reconnects when it
/// next needs the stream. Also bounds a stalled Noise handshake.
const IDLE_TIMEOUT: Duration = Duration::from_mins(5);
/// How long to wait after a failed accept (usually out of file descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(500);

#[derive(Debug, PartialEq, Eq)]
struct Options {
    data: PathBuf,
    onion_socket: PathBuf,
    direct: Option<SocketAddr>,
    max_gb: Option<u64>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let (mut data, mut onion_socket, mut direct, mut max_gb) = (None, None, None, None);
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| io::Error::other(USAGE))?;
        match arg.as_str() {
            "--data" => data = Some(PathBuf::from(value)),
            "--onion-socket" => onion_socket = Some(PathBuf::from(value)),
            "--direct" => {
                direct = Some(
                    value
                        .parse()
                        .map_err(|_| io::Error::other("--direct takes an IP address and port"))?,
                );
            }
            "--max-gb" => max_gb = Some(value.parse().map_err(|_| io::Error::other(USAGE))?),
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    Ok(Options {
        data: data.ok_or_else(|| io::Error::other(USAGE))?,
        onion_socket: onion_socket.ok_or_else(|| io::Error::other(USAGE))?,
        direct,
        max_gb,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-store: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    purple_harden::harden()?;
    let options = parse_args(std::env::args().skip(1))?;
    fs::create_dir_all(&options.data)?;
    let key = options
        .direct
        .map(|_| load_or_create_key(&options.data))
        .transpose()?;
    let boxes = options.data.join("boxes");
    fs::create_dir_all(&boxes)?;
    match fs::remove_file(&options.onion_socket) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        Ok(()) | Err(_) => {}
    }
    let onion = UnixListener::bind(&options.onion_socket)?;
    let direct = options.direct.map(TcpListener::bind).transpose()?;
    let socket_dir = options
        .onion_socket
        .parent()
        .unwrap_or_else(|| Path::new("/"));
    restrict(&Policy {
        writable: &[options.data.as_path(), socket_dir],
        network: Network::Allowed,
    })?;
    let limits = Limits {
        max_bytes: options
            .max_gb
            .map_or(DEFAULT_LIMITS.max_bytes, |gb| gb.saturating_mul(1 << 30)),
        ..DEFAULT_LIMITS
    };
    let store = Arc::new(SharedStore(Mutex::new(DiskStore::open(
        &boxes,
        limits,
        unix_now()?,
    )?)));
    if let (Some(listener), Some((private, public))) = (direct, key) {
        eprintln!("purple-store: direct key {}", hex(&public));
        let store = Arc::clone(&store);
        thread::spawn(move || {
            accept_all(listener.incoming(), ACCEPT_BACKOFF, |conn| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    let served = conn
                        .set_read_timeout(Some(IDLE_TIMEOUT))
                        .and_then(|()| NoiseStream::server(conn, &private))
                        .and_then(|mut s| serve_provider(&mut s, &*store, Some(WRITES_PER_SEC)));
                    if let Err(err) = served {
                        eprintln!("purple-store: direct client: {err}");
                    }
                });
            });
        });
    }
    accept_all(onion.incoming(), ACCEPT_BACKOFF, |mut conn| {
        let store = Arc::clone(&store);
        thread::spawn(move || {
            let served = conn
                .set_read_timeout(Some(IDLE_TIMEOUT))
                .and_then(|()| serve_provider(&mut conn, &*store, Some(WRITES_PER_SEC)));
            if let Err(err) = served {
                eprintln!("purple-store: client: {err}");
            }
        });
    });
    Ok(())
}

/// Hand each accepted connection to `serve`. A failed accept (out of file descriptors,
/// say) is logged and waited out, never fatal and never a busy loop.
fn accept_all<S>(
    incoming: impl IntoIterator<Item = io::Result<S>>,
    backoff: Duration,
    mut serve: impl FnMut(S),
) {
    for conn in incoming {
        match conn {
            Ok(conn) => serve(conn),
            Err(err) => {
                eprintln!("purple-store: accept failed: {err}");
                thread::sleep(backoff);
            }
        }
    }
}

/// The direct port's static key, made on first run and kept readable only by the store.
fn load_or_create_key(data: &Path) -> io::Result<([u8; 32], [u8; 32])> {
    let path = data.join(KEY_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let (private, public) = bytes
                .split_first_chunk::<32>()
                .and_then(|(private, rest)| Some((*private, *rest.first_chunk::<32>()?)))
                .ok_or_else(|| io::Error::other("noise.key is damaged"))?;
            Ok((private, public))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let (private, public) = noise_keypair()?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&private)?;
            file.write_all(&public)?;
            Ok((private, public))
        }
        Err(err) => Err(err),
    }
}

fn unix_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(io::Error::other)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String can't fail.
        write!(out, "{b:02x}").ok();
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> io::Result<Options> {
        parse_args(args.iter().map(|&a| a.to_owned()))
    }

    #[test]
    fn parses_options() {
        let o = parse(&[
            "--data",
            "/d",
            "--onion-socket",
            "/s/onion.sock",
            "--direct",
            "192.0.2.1:4443",
        ])
        .unwrap();
        assert_eq!(o.direct, Some("192.0.2.1:4443".parse().unwrap()));
        assert!(
            parse(&["--data", "/d"]).is_err(),
            "the onion socket is required"
        );
        assert!(
            parse(&[
                "--data",
                "/d",
                "--onion-socket",
                "/s",
                "--direct",
                "store.example:4443"
            ])
            .is_err(),
            "no hostnames"
        );
    }

    #[test]
    fn accept_errors_are_survived() {
        let incoming = vec![
            Err(io::Error::other("too many open files")),
            Ok(1),
            Err(io::Error::other("too many open files")),
            Ok(2),
        ];
        let mut served = Vec::new();
        accept_all(incoming, Duration::ZERO, |conn| served.push(conn));
        assert_eq!(served, [1, 2]);
    }

    #[test]
    fn the_key_is_kept_across_runs() {
        let dir = std::env::temp_dir().join(format!("purple-store-key-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        let first = load_or_create_key(&dir).unwrap();
        assert_eq!(load_or_create_key(&dir).unwrap(), first);
        fs::remove_dir_all(&dir).unwrap();
    }
}
