//! Core's side of the route to the store: forwards the user's choices to purple-torctl,
//! carries its status and notices to the UI, and turns its `GoDirect` into a relay started
//! by the launcher and only then a switch in purple-net.

use std::io::{self, Write};
use std::os::unix::net::UnixStream;

use purple_ipc::NetChoice;
use purple_ipc::NetMsg;
use purple_ipc::torctl::{LauncherMsg, TorCtlMsg};
use purple_ipc::ui::{UiCmd, UiEvent};

pub(crate) const RELAY_FAILED: &str =
    "the direct connection couldn't start; try /direct again or paste bridges";
pub(crate) const TORCTL_GONE: &str =
    "network status is unavailable (purple-torctl stopped); messages still go over Tor";
pub(crate) const NO_TORCTL: &str = "this purple isn't choosing routes right now";

/// The sockets to purple-torctl and the launcher, while they last.
#[derive(Debug)]
pub(crate) struct TorRoute {
    torctl: Option<UnixStream>,
    launcher: Option<UnixStream>,
}

fn notice(ui: &mut impl Write, text: &str) -> io::Result<()> {
    UiEvent::Notice {
        text: text.to_owned(),
    }
    .write_to(ui)
}

impl TorRoute {
    pub(crate) const fn new(torctl: Option<UnixStream>, launcher: Option<UnixStream>) -> Self {
        Self { torctl, launcher }
    }

    /// Clones of the two sockets, for reader threads.
    pub(crate) fn readers(&self) -> io::Result<(Option<UnixStream>, Option<UnixStream>)> {
        let torctl = self
            .torctl
            .as_ref()
            .map(UnixStream::try_clone)
            .transpose()?;
        let launcher = self
            .launcher
            .as_ref()
            .map(UnixStream::try_clone)
            .transpose()?;
        Ok((torctl, launcher))
    }

    /// Send `cmd` to torctl if it's a route choice. Returns whether it was one.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "every other command is for the messenger"
    )]
    pub(crate) fn choose(&mut self, cmd: &UiCmd, ui: &mut impl Write) -> io::Result<bool> {
        let choice = match cmd {
            UiCmd::UseDirect => NetChoice::Direct,
            UiCmd::AddBridges { lines } => NetChoice::Bridges(lines.clone()),
            _ => return Ok(false),
        };
        let sent = self
            .torctl
            .as_mut()
            .map(|t| TorCtlMsg::Choose(choice).write_to(t));
        match sent {
            Some(Ok(())) => {}
            Some(Err(_)) => {
                self.torctl = None;
                notice(ui, TORCTL_GONE)?;
            }
            None => notice(ui, NO_TORCTL)?,
        }
        Ok(true)
    }

    /// Something from torctl, or the end of its socket.
    pub(crate) fn on_torctl(
        &mut self,
        got: &io::Result<Option<TorCtlMsg>>,
        ui: &mut impl Write,
    ) -> io::Result<()> {
        match got {
            Ok(Some(TorCtlMsg::Status(status))) => {
                UiEvent::Network { status: *status }.write_to(ui)
            }
            Ok(Some(TorCtlMsg::Notice(n))) => notice(ui, n.text()),
            Ok(Some(TorCtlMsg::GoDirect)) => {
                let asked = self
                    .launcher
                    .as_mut()
                    .map(|l| LauncherMsg::StartRelay.write_to(l));
                if !matches!(asked, Some(Ok(()))) {
                    self.launcher = None;
                    self.tell_torctl(&TorCtlMsg::DirectFailed);
                    notice(ui, RELAY_FAILED)?;
                }
                Ok(())
            }
            Ok(Some(TorCtlMsg::Choose(_) | TorCtlMsg::DirectUp | TorCtlMsg::DirectFailed)) => {
                eprintln!("purple-core: purple-torctl sent a message only core may send");
                Ok(())
            }
            Ok(None) | Err(_) => {
                if self.torctl.take().is_some() {
                    notice(ui, TORCTL_GONE)?;
                }
                Ok(())
            }
        }
    }

    /// Something from the launcher, or the end of its socket.
    pub(crate) fn on_launcher(
        &mut self,
        got: &io::Result<Option<LauncherMsg>>,
        net: &mut impl Write,
        ui: &mut impl Write,
    ) -> io::Result<()> {
        match got {
            Ok(Some(LauncherMsg::RelayUp)) => {
                NetMsg::UseDirect.write_to(net)?;
                self.tell_torctl(&TorCtlMsg::DirectUp);
                Ok(())
            }
            Ok(Some(LauncherMsg::RelayFailed)) => {
                self.tell_torctl(&TorCtlMsg::DirectFailed);
                notice(ui, RELAY_FAILED)
            }
            Ok(Some(LauncherMsg::StartRelay)) => {
                eprintln!("purple-core: the launcher sent a message only core may send");
                Ok(())
            }
            Ok(None) | Err(_) => {
                self.launcher = None;
                Ok(())
            }
        }
    }

    fn tell_torctl(&mut self, msg: &TorCtlMsg) {
        if let Some(t) = self.torctl.as_mut()
            && msg.write_to(t).is_err()
        {
            self.torctl = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use purple_ipc::torctl::{LauncherMsg, Notice, TorCtlMsg};
    use purple_ipc::ui::{UiCmd, UiEvent};
    use purple_ipc::{NetChoice, NetMsg};

    use super::*;

    struct Peers {
        route: TorRoute,
        torctl: UnixStream,
        launcher: UnixStream,
    }

    fn peers() -> Peers {
        let (core_t, torctl) = UnixStream::pair().unwrap();
        let (core_l, launcher) = UnixStream::pair().unwrap();
        for s in [&torctl, &launcher] {
            s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
        }
        Peers {
            route: TorRoute::new(Some(core_t), Some(core_l)),
            torctl,
            launcher,
        }
    }

    fn ui_events(bytes: &[u8]) -> Vec<UiEvent> {
        let mut r = bytes;
        std::iter::from_fn(|| UiEvent::read_from(&mut r).unwrap()).collect()
    }

    #[test]
    fn direct_goes_torctl_then_launcher_then_net() {
        let mut p = peers();
        let (mut net, mut ui) = (Vec::new(), Vec::new());
        assert!(p.route.choose(&UiCmd::UseDirect, &mut ui).unwrap());
        assert_eq!(
            TorCtlMsg::read_from(&mut p.torctl).unwrap(),
            Some(TorCtlMsg::Choose(NetChoice::Direct))
        );
        p.route
            .on_torctl(&Ok(Some(TorCtlMsg::GoDirect)), &mut ui)
            .unwrap();
        assert_eq!(
            LauncherMsg::read_from(&mut p.launcher).unwrap(),
            Some(LauncherMsg::StartRelay)
        );
        assert!(
            net.is_empty(),
            "nothing to purple-net before the relay is up"
        );
        p.route
            .on_launcher(&Ok(Some(LauncherMsg::RelayUp)), &mut net, &mut ui)
            .unwrap();
        assert_eq!(
            NetMsg::read_from(&mut &net[..]).unwrap(),
            Some(NetMsg::UseDirect)
        );
        assert_eq!(
            TorCtlMsg::read_from(&mut p.torctl).unwrap(),
            Some(TorCtlMsg::DirectUp)
        );
    }

    #[test]
    fn a_failed_relay_never_reaches_net() {
        let mut p = peers();
        let (mut net, mut ui) = (Vec::new(), Vec::new());
        p.route
            .on_torctl(&Ok(Some(TorCtlMsg::GoDirect)), &mut ui)
            .unwrap();
        LauncherMsg::read_from(&mut p.launcher).unwrap();
        p.route
            .on_launcher(&Ok(Some(LauncherMsg::RelayFailed)), &mut net, &mut ui)
            .unwrap();
        assert!(net.is_empty());
        assert_eq!(
            TorCtlMsg::read_from(&mut p.torctl).unwrap(),
            Some(TorCtlMsg::DirectFailed)
        );
        assert_eq!(
            ui_events(&ui),
            [UiEvent::Notice {
                text: RELAY_FAILED.into()
            }]
        );
    }

    #[test]
    fn relay_thread_gone_counts_as_failed() {
        let mut p = peers();
        let (mut net, mut ui) = (Vec::new(), Vec::new());
        drop(p.launcher);
        p.route.on_launcher(&Ok(None), &mut net, &mut ui).unwrap();
        p.route
            .on_torctl(&Ok(Some(TorCtlMsg::GoDirect)), &mut ui)
            .unwrap();
        assert!(net.is_empty());
        assert_eq!(
            TorCtlMsg::read_from(&mut p.torctl).unwrap(),
            Some(TorCtlMsg::DirectFailed)
        );
    }

    #[test]
    fn notices_become_their_text() {
        let mut p = peers();
        let mut ui = Vec::new();
        p.route
            .on_torctl(&Ok(Some(TorCtlMsg::Notice(Notice::AlreadyDirect))), &mut ui)
            .unwrap();
        assert_eq!(
            ui_events(&ui),
            [UiEvent::Notice {
                text: Notice::AlreadyDirect.text().into()
            }]
        );
    }

    #[test]
    fn torctl_gone_is_told_once() {
        let mut p = peers();
        let mut ui = Vec::new();
        p.route.on_torctl(&Ok(None), &mut ui).unwrap();
        p.route
            .on_torctl(&Err(io::Error::other("bad frame")), &mut ui)
            .unwrap();
        assert!(p.route.choose(&UiCmd::UseDirect, &mut ui).unwrap());
        assert_eq!(
            ui_events(&ui),
            [
                UiEvent::Notice {
                    text: TORCTL_GONE.into()
                },
                UiEvent::Notice {
                    text: NO_TORCTL.into()
                },
            ]
        );
    }

    #[test]
    fn other_commands_are_not_route_choices() {
        let mut p = peers();
        assert!(
            !p.route
                .choose(&UiCmd::GroupNew { group: "g".into() }, &mut Vec::new())
                .unwrap()
        );
    }
}
