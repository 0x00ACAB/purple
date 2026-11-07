//! Just enough of tor's control protocol: cookie auth, bootstrap progress, and switching
//! bridges on or off.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Longest bridge line accepted.
const MAX_BRIDGE_LINE: usize = 1000;

/// A connection to tor's control socket.
#[derive(Debug)]
pub struct Control {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Control {
    /// Connect and authenticate with the cookie file tor wrote.
    ///
    /// # Errors
    /// Fails if the socket or cookie can't be read, or tor rejects the cookie.
    pub fn connect(socket: &Path, cookie: &Path) -> io::Result<Self> {
        let writer = UnixStream::connect(socket)?;
        let mut control = Self {
            reader: BufReader::new(writer.try_clone()?),
            writer,
        };
        let cookie = fs::read(cookie)?.iter().fold(String::new(), |mut out, b| {
            // Writing to a String can't fail.
            write!(out, "{b:02x}").ok();
            out
        });
        control.command(&format!("AUTHENTICATE {cookie}"))?;
        Ok(control)
    }

    /// Tor's bootstrap progress, 0 to 100.
    ///
    /// # Errors
    /// Fails if tor errors or the reply has no progress.
    pub fn bootstrap(&mut self) -> io::Result<u8> {
        let lines = self.command("GETINFO status/bootstrap-phase")?;
        lines
            .iter()
            .find_map(|line| {
                let at = line.find("PROGRESS=")?;
                let digits: String = line
                    .get(at.saturating_add(9)..)?
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                digits.parse::<u8>().ok().filter(|p| *p <= 100)
            })
            .ok_or_else(|| io::Error::other("tor's bootstrap reply had no progress"))
    }

    /// Use `lines` as bridges, run through the pluggable transport `plugin`
    /// (for example `obfs4 exec /usr/bin/lyrebird`).
    ///
    /// # Errors
    /// Fails on a bad bridge line or if tor rejects the change.
    pub fn use_bridges(&mut self, plugin: &str, lines: &[String]) -> io::Result<()> {
        check_bridge_line(plugin)?;
        let mut cmd = format!("SETCONF UseBridges=1 ClientTransportPlugin=\"{plugin}\"");
        for line in lines {
            check_bridge_line(line)?;
            write!(cmd, " Bridge=\"{line}\"").ok();
        }
        self.command(&cmd).map(drop)
    }

    /// Go back to connecting without bridges.
    ///
    /// # Errors
    /// Fails if tor rejects the change.
    pub fn no_bridges(&mut self) -> io::Result<()> {
        self.command("SETCONF UseBridges=0").map(drop)
    }

    /// Send one command and collect its reply lines, failing on any non-250 reply.
    fn command(&mut self, cmd: &str) -> io::Result<Vec<String>> {
        self.writer.write_all(format!("{cmd}\r\n").as_bytes())?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tor closed its control socket",
                ));
            }
            let line = line.trim_end().to_owned();
            if !line.starts_with("250") {
                return Err(io::Error::other(format!("tor said: {line}")));
            }
            // "250 " ends the reply; "250-" and "250+" continue it. A "250+" data reply would
            // also end with a "." line, but none of the commands sent here get one.
            let last = line.get(3..4) == Some(" ");
            lines.push(line);
            if last {
                return Ok(lines);
            }
        }
    }
}

/// Accept only bridge lines that can't break out of their quotes or the command: printable
/// ASCII without quotes or backslashes.
///
/// # Errors
/// Fails on an empty, overlong or unsafe line.
pub fn check_bridge_line(line: &str) -> io::Result<()> {
    let safe = !line.is_empty()
        && line.len() <= MAX_BRIDGE_LINE
        && line
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\');
    if safe {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "that isn't a valid bridge line",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::*;

    fn paths(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("purple-ctl-{name}-{}", std::process::id()));
        fs::remove_file(base.with_extension("sock")).ok();
        fs::write(base.with_extension("cookie"), [0xAB; 32]).unwrap();
        (base.with_extension("sock"), base.with_extension("cookie"))
    }

    /// A control port that answers each command from `script` in turn and records them.
    fn fake_control(
        path: &Path,
        script: Vec<&'static str>,
    ) -> std::thread::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            let mut w = c.try_clone().unwrap();
            let mut lines = BufReader::new(c).lines();
            let mut seen = Vec::new();
            for answer in script {
                seen.push(lines.next().unwrap().unwrap());
                w.write_all(answer.as_bytes()).unwrap();
            }
            seen
        })
    }

    #[test]
    fn authenticates_with_the_cookie_and_reads_bootstrap() {
        let (sock, cookie) = paths("boot");
        let server = fake_control(
            &sock,
            vec![
                "250 OK\r\n",
                "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY=\"Loading\"\r\n250 OK\r\n",
            ],
        );
        let mut c = Control::connect(&sock, &cookie).unwrap();
        assert_eq!(c.bootstrap().unwrap(), 45);
        let seen = server.join().unwrap();
        assert_eq!(seen[0], format!("AUTHENTICATE {}", "ab".repeat(32)));
        assert_eq!(seen[1], "GETINFO status/bootstrap-phase");
    }

    #[test]
    fn sets_bridges_quoted() {
        let (sock, cookie) = paths("bridges");
        let server = fake_control(&sock, vec!["250 OK\r\n", "250 OK\r\n"]);
        let mut c = Control::connect(&sock, &cookie).unwrap();
        c.use_bridges(
            "obfs4 exec /usr/bin/lyrebird",
            &["obfs4 192.0.2.1:443 F00 cert=abc iat-mode=0".into()],
        )
        .unwrap();
        let seen = server.join().unwrap();
        assert_eq!(
            seen[1],
            "SETCONF UseBridges=1 ClientTransportPlugin=\"obfs4 exec /usr/bin/lyrebird\" \
             Bridge=\"obfs4 192.0.2.1:443 F00 cert=abc iat-mode=0\""
        );
    }

    #[test]
    fn errors_from_tor_are_errors() {
        let (sock, cookie) = paths("err");
        let server = fake_control(&sock, vec!["515 Authentication failed\r\n"]);
        assert!(Control::connect(&sock, &cookie).is_err());
        server.join().unwrap();
    }

    #[test]
    fn bridge_lines_cannot_inject_commands() {
        assert!(check_bridge_line("obfs4 192.0.2.1:443 F00 cert=a iat-mode=0").is_ok());
        assert!(check_bridge_line("obfs4 1.2.3.4:1\r\nSIGNAL HALT").is_err());
        assert!(check_bridge_line("x\" Bridge=\"y").is_err());
        assert!(check_bridge_line("back\\slash").is_err());
        assert!(check_bridge_line("").is_err());
        assert!(check_bridge_line(&"a".repeat(1001)).is_err());
    }
}
