//! purple-transporter: the one process that may reach the store without Tor, used only after the
//! user chose a direct connection. It pipes each connection on its Unix socket to one fixed
//! IP address and port; it never sees plaintext (purple-subspace runs Noise through it) and can't
//! be pointed anywhere else.
//!
//! Usage: `purple-transporter --listen <socket> --connect <ip:port>`.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use purple_shields::sandbox::{Network, Policy, restrict};

const USAGE: &str = "usage: purple-transporter --listen <socket> --connect <ip:port>";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct Options {
    listen: PathBuf,
    connect: SocketAddr,
}

fn parse(args: &[&str]) -> io::Result<Options> {
    match args {
        ["--listen", listen, "--connect", connect] => Ok(Options {
            listen: PathBuf::from(listen),
            connect: connect
                .parse()
                .map_err(|_| io::Error::other("--connect takes an IP address and port"))?,
        }),
        _ => Err(io::Error::other(USAGE)),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-transporter: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    purple_shields::harden()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let options = parse(&args)?;
    match std::fs::remove_file(&options.listen) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        Ok(()) | Err(_) => {}
    }
    let listener = UnixListener::bind(&options.listen)?;
    restrict(&Policy {
        writable: &[],
        network: Network::Allowed,
    })?;
    for conn in listener.incoming() {
        let conn = conn?;
        let target = options.connect;
        thread::spawn(move || {
            let piped = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)
                .and_then(|tcp| pipe(conn, tcp));
            if let Err(err) = piped {
                eprintln!("purple-transporter: {err}");
            }
        });
    }
    Ok(())
}

/// Copy bytes both ways until either side closes, then close both.
fn pipe(unix: UnixStream, tcp: TcpStream) -> io::Result<()> {
    let (mut unix_r, mut tcp_w) = (unix.try_clone()?, tcp.try_clone()?);
    let up = thread::spawn(move || {
        let copied = io::copy(&mut unix_r, &mut tcp_w);
        tcp_w.shutdown(Shutdown::Both).ok();
        copied
    });
    let (mut tcp_r, mut unix_w) = (tcp, unix);
    let down = io::copy(&mut tcp_r, &mut unix_w);
    unix_w.shutdown(Shutdown::Both).ok();
    up.join()
        .map_err(|_| io::Error::other("relay thread panicked"))??;
    down.map(drop)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use super::*;

    #[test]
    fn pipes_both_ways_until_a_side_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            c.read_exact(&mut buf).unwrap();
            c.write_all(&buf).unwrap();
        });
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let tcp = TcpStream::connect(addr).unwrap();
        let relay = thread::spawn(move || pipe(theirs, tcp));
        ours.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        ours.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        echo.join().unwrap();
        drop(ours);
        relay.join().unwrap().unwrap();
    }

    #[test]
    fn only_ip_literals() {
        assert!(parse(&["--listen", "/r/relay.sock", "--connect", "192.0.2.1:4443"]).is_ok());
        assert!(
            parse(&[
                "--listen",
                "/r/relay.sock",
                "--connect",
                "store.example:4443"
            ])
            .is_err()
        );
    }
}
