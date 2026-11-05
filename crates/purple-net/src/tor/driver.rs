//! Watches tor's bootstrap through the control socket and walks the fallback chain:
//! switching bridges, reporting status to core, and moving connections to the direct route
//! when the user says so.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use purple_ipc::{NetChoice, NetStatus, Route};

use super::bridges;
use super::control::Control;
use super::fallback::{Action, Fallback};
use super::transport::{Dialer, DirectDial, OnionDial};

/// Where tor's sockets are and how to reach the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorSetup {
    /// tor's SOCKS socket.
    pub socks: PathBuf,
    /// tor's control socket.
    pub control: PathBuf,
    /// The cookie file for the control socket.
    pub cookie: PathBuf,
    /// The store's onion address.
    pub host: String,
    /// Its port.
    pub port: u16,
    /// purple-relay's socket and the store's Noise key, if the store has a direct port.
    pub direct: Option<(PathBuf, [u8; 32])>,
}

impl TorSetup {
    /// The onion dialer for this setup.
    #[must_use]
    pub fn onion(&self) -> OnionDial {
        OnionDial {
            socks: self.socks.clone(),
            host: self.host.clone(),
            port: self.port,
        }
    }
}

/// The plugin for pasted bridge lines: they must all use one supported transport.
///
/// # Errors
/// Says why the lines can't be used.
pub fn pasted_plugin(lines: &[String]) -> Result<&'static str, &'static str> {
    let mut kinds = lines
        .iter()
        .map(|l| l.split_whitespace().next().unwrap_or(""));
    let first = kinds.next().ok_or("no bridge lines")?;
    if kinds.any(|k| k != first) {
        return Err("paste bridges of one type at a time");
    }
    let route = match first {
        "obfs4" => Route::Obfs4,
        "snowflake" => Route::Snowflake,
        "webtunnel" => Route::WebTunnel,
        _ => return Err("purple only supports obfs4, snowflake and webtunnel bridges"),
    };
    bridges::plugin(route).ok_or("purple only supports obfs4, snowflake and webtunnel bridges")
}

/// Run the fallback chain until `choices` disconnects (purple-net is exiting). Checks
/// bootstrap progress every `every`.
pub fn drive(
    setup: &TorSetup,
    dialer: &Dialer,
    status: &Sender<NetStatus>,
    choices: &Receiver<NetChoice>,
    every: Duration,
) {
    let mut fallback = Fallback::new(
        &bridges::available(),
        setup.direct.is_some(),
        Instant::now(),
    );
    let mut control: Option<Control> = None;
    loop {
        let actions = match choices.recv_timeout(every) {
            Ok(choice) => fallback.choose(choice, Instant::now()),
            Err(RecvTimeoutError::Disconnected) => return,
            Err(RecvTimeoutError::Timeout) => {
                if control.is_none() {
                    control = Control::connect(&setup.control, &setup.cookie).ok();
                }
                let percent = control.as_mut().and_then(|c| c.bootstrap().ok());
                if percent.is_none() {
                    // tor isn't answering yet (or any more): no progress.
                    control = None;
                }
                fallback.progress(percent.unwrap_or(0), Instant::now())
            }
        };
        for action in actions {
            act(action, setup, dialer, status, control.as_mut());
        }
    }
}

fn act(
    action: Action,
    setup: &TorSetup,
    dialer: &Dialer,
    status: &Sender<NetStatus>,
    control: Option<&mut Control>,
) {
    let result = match action {
        Action::Report(s) => {
            status.send(s).ok();
            Ok(())
        }
        Action::Say(text) => {
            eprintln!("purple-net: {text}");
            Ok(())
        }
        Action::UseDirect => {
            if let Some((relay, key)) = &setup.direct {
                dialer.set(Arc::new(DirectDial {
                    relay: relay.clone(),
                    key: *key,
                }));
            }
            Ok(())
        }
        Action::UseBridges(route) => match (control, bridges::plugin(route)) {
            (Some(c), Some(plugin)) => {
                let lines: Vec<String> = bridges::builtin(route)
                    .iter()
                    .map(|l| (*l).to_owned())
                    .collect();
                c.use_bridges(plugin, &lines)
            }
            _ => Ok(()),
        },
        Action::UsePasted(lines) => match (control, pasted_plugin(&lines)) {
            (Some(c), Ok(plugin)) => c.use_bridges(plugin, &lines),
            (_, Err(why)) => {
                eprintln!("purple-net: {why}");
                Ok(())
            }
            (None, Ok(_)) => Ok(()),
        },
        Action::NoBridges => control.map_or(Ok(()), Control::no_bridges),
    };
    if let Err(err) = result {
        eprintln!("purple-net: tor refused a change: {err}");
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn pasted_lines_pick_their_transport() {
        let obfs4 = vec!["obfs4 192.0.2.1:443 F cert=c iat-mode=0".to_owned()];
        assert_eq!(pasted_plugin(&obfs4), Ok("obfs4 exec /usr/bin/lyrebird"));
        let snow = vec!["snowflake 192.0.2.3:80 F".to_owned()];
        assert_eq!(pasted_plugin(&snow), Ok("snowflake exec /usr/bin/lyrebird"));
        let mixed = vec![obfs4[0].clone(), snow[0].clone()];
        assert!(pasted_plugin(&mixed).is_err());
        assert!(pasted_plugin(&["meek_lite 192.0.2.1:2 F".to_owned()]).is_err());
    }

    #[test]
    fn reports_connected_when_tor_finishes_bootstrapping() {
        let dir = std::env::temp_dir().join(format!("purple-drive-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let (ctl, cookie) = (dir.join("control.sock"), dir.join("control.cookie"));
        std::fs::write(&cookie, [1; 32]).unwrap();
        let listener = UnixListener::bind(&ctl).unwrap();
        std::thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            let mut w = c.try_clone().unwrap();
            for line in BufReader::new(c).lines() {
                let answer = if line.unwrap().starts_with("GETINFO") {
                    "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"
                } else {
                    "250 OK\r\n"
                };
                if w.write_all(answer.as_bytes()).is_err() {
                    return;
                }
            }
        });
        let setup = TorSetup {
            socks: dir.join("socks.sock"),
            control: ctl,
            cookie,
            host: "x.onion".into(),
            port: 80,
            direct: None,
        };
        let dialer = Dialer::new(Arc::new(OnionDial {
            socks: setup.socks.clone(),
            host: setup.host.clone(),
            port: 80,
        }));
        let (status_tx, status_rx) = mpsc::channel();
        let (choice_tx, choice_rx) = mpsc::channel();
        let driver = std::thread::spawn(move || {
            drive(
                &setup,
                &dialer,
                &status_tx,
                &choice_rx,
                Duration::from_millis(10),
            );
        });
        assert_eq!(
            status_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            NetStatus::Connected { route: Route::Tor }
        );
        drop(choice_tx);
        driver.join().unwrap();
    }
}
