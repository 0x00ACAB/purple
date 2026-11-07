//! The loop: read tor's bootstrap progress, walk the fallback, carry out its actions, and
//! answer core.

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use purple_combadge::Route;
use purple_combadge::torctl::TorCtlMsg;

use crate::bridges;
use crate::control::Control;
use crate::fallback::{Action, Fallback};

/// Where tor's control socket is and what the fallback may use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    /// tor's control socket.
    pub control: PathBuf,
    /// Its cookie file.
    pub cookie: PathBuf,
    /// Whether the store config has a direct address.
    pub direct_available: bool,
    /// Built-in bridge types to try, found before the sandbox closes.
    pub bridges: Vec<Route>,
    /// How long a route may go without progress.
    pub stall: Duration,
}

/// Run the fallback chain, checking tor every `every`, until `from_core` disconnects.
///
/// # Errors
/// Fails if core can't be written to.
pub fn drive(
    setup: &Setup,
    from_core: &Receiver<TorCtlMsg>,
    to_core: &mut impl Write,
    every: Duration,
) -> io::Result<()> {
    let mut fallback = Fallback::with_stall(
        &setup.bridges,
        setup.direct_available,
        Instant::now(),
        setup.stall,
    );
    let mut control: Option<Control> = None;
    loop {
        let actions = match from_core.recv_timeout(every) {
            Ok(TorCtlMsg::Choose(choice)) => fallback.choose(choice, Instant::now()),
            Ok(TorCtlMsg::DirectUp) => fallback.direct_up(),
            Ok(TorCtlMsg::DirectFailed) => fallback.direct_failed(),
            Ok(TorCtlMsg::Status(_) | TorCtlMsg::GoDirect | TorCtlMsg::Notice(_)) => {
                eprintln!("purple-cloak: core sent a message only torctl may send");
                Vec::new()
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
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
            act(action, to_core, control.as_mut())?;
        }
    }
}

fn act(action: Action, to_core: &mut impl Write, control: Option<&mut Control>) -> io::Result<()> {
    let changed = match action {
        Action::Report(status) => return TorCtlMsg::Status(status).write_to(to_core),
        Action::Notice(notice) => return TorCtlMsg::Notice(notice).write_to(to_core),
        Action::GoDirect => return TorCtlMsg::GoDirect.write_to(to_core),
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
        Action::UsePasted { plugin, lines } => {
            control.map_or(Ok(()), |c| c.use_bridges(plugin, &lines))
        }
        Action::NoBridges => control.map_or(Ok(()), Control::no_bridges),
    };
    if let Err(err) = changed {
        eprintln!("purple-cloak: tor refused a change: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::mpsc::{self, Sender};
    use std::thread;

    use purple_combadge::torctl::Notice;
    use purple_combadge::{NetChoice, NetStatus, Route};

    use super::*;
    use crate::fallback::STALL;

    /// A tor control socket answering every GETINFO with `progress`.
    fn fake_tor(name: &str, progress: u8) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("purple-cloak-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let (ctl, cookie) = (dir.join("control.sock"), dir.join("control.cookie"));
        std::fs::write(&cookie, [1; 32]).unwrap();
        let listener = UnixListener::bind(&ctl).unwrap();
        thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            let mut w = c.try_clone().unwrap();
            for line in BufReader::new(c).lines() {
                let answer = if line.unwrap().starts_with("GETINFO") {
                    format!(
                        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG=x SUMMARY=\"x\"\r\n250 OK\r\n"
                    )
                } else {
                    "250 OK\r\n".to_owned()
                };
                if w.write_all(answer.as_bytes()).is_err() {
                    return;
                }
            }
        });
        (ctl, cookie)
    }

    /// Run the driver; returns core's side: a sender for its messages and a stream to read
    /// torctl's.
    fn run(
        name: &str,
        progress: u8,
        bridges: Vec<Route>,
        direct: bool,
    ) -> (Sender<TorCtlMsg>, UnixStream) {
        let (control, cookie) = fake_tor(name, progress);
        let setup = Setup {
            control,
            cookie,
            direct_available: direct,
            bridges,
            stall: Duration::from_millis(50),
        };
        let (tx, rx) = mpsc::channel();
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        theirs
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        thread::spawn(move || drive(&setup, &rx, &mut ours, Duration::from_millis(10)));
        (tx, theirs)
    }

    fn next(from: &mut UnixStream) -> TorCtlMsg {
        TorCtlMsg::read_from(from).unwrap().unwrap()
    }

    #[test]
    fn reports_connected_when_tor_finishes_bootstrapping() {
        let (_tx, mut core) = run("boot", 100, vec![], false);
        assert_eq!(
            next(&mut core),
            TorCtlMsg::Status(NetStatus::Connected { route: Route::Tor })
        );
    }

    #[test]
    fn stalls_walk_the_bridges_it_was_given_then_block() {
        let (_tx, mut core) = run("stall", 0, vec![Route::Obfs4], false);
        assert_eq!(
            next(&mut core),
            TorCtlMsg::Status(NetStatus::Connecting {
                route: Route::Obfs4,
                percent: 0
            })
        );
        assert_eq!(next(&mut core), TorCtlMsg::Status(NetStatus::Blocked));
    }

    #[test]
    fn direct_goes_through_core_and_can_fail() {
        let (tx, mut core) = run("direct", 0, vec![], true);
        assert_eq!(next(&mut core), TorCtlMsg::Status(NetStatus::Blocked));
        tx.send(TorCtlMsg::Choose(NetChoice::Direct)).unwrap();
        assert_eq!(next(&mut core), TorCtlMsg::GoDirect);
        tx.send(TorCtlMsg::DirectFailed).unwrap();
        assert_eq!(next(&mut core), TorCtlMsg::Status(NetStatus::Blocked));
        tx.send(TorCtlMsg::Choose(NetChoice::Direct)).unwrap();
        assert_eq!(next(&mut core), TorCtlMsg::GoDirect);
        tx.send(TorCtlMsg::DirectUp).unwrap();
        assert_eq!(
            next(&mut core),
            TorCtlMsg::Status(NetStatus::Connected {
                route: Route::Direct
            })
        );
        tx.send(TorCtlMsg::Choose(NetChoice::Direct)).unwrap();
        assert_eq!(next(&mut core), TorCtlMsg::Notice(Notice::AlreadyDirect));
    }

    #[test]
    fn returns_when_core_goes() {
        let (control, cookie) = fake_tor("gone", 0);
        let setup = Setup {
            control,
            cookie,
            direct_available: false,
            bridges: vec![],
            stall: STALL,
        };
        let (tx, rx) = mpsc::channel();
        drop(tx);
        assert!(drive(&setup, &rx, &mut Vec::new(), Duration::from_millis(10)).is_ok());
    }
}
