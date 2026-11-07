//! Messages between purple-data and purple-cloak, and between purple-data and the
//! launcher.
//!
//! Layout: a tag byte, then the body. Same frames as [`crate::NetMsg`].

use std::io::{self, Read, Write};

use crate::{MAX_BRIDGE_TEXT, NetChoice, NetStatus, invalid, read_frame, write_frame};

const MAX_TORCTL_FRAME: usize = 2 + MAX_BRIDGE_TEXT;
const MAX_LAUNCHER_FRAME: usize = 1;

const TAG_STATUS: u8 = 1;
const TAG_GO_DIRECT: u8 = 2;
const TAG_NOTICE: u8 = 3;
const TAG_CHOOSE: u8 = 4;
const TAG_DIRECT_UP: u8 = 5;
const TAG_DIRECT_FAILED: u8 = 6;

const TAG_START_RELAY: u8 = 1;
const TAG_RELAY_UP: u8 = 2;
const TAG_RELAY_FAILED: u8 = 3;

/// Something torctl tells the user that changes nothing. Core shows [`Notice::text`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A choice came before every route failed.
    StillTrying,
    /// `/direct`, but the store config has no direct address.
    NoDirectAddress,
    /// `/direct` or `/bridges` after going direct.
    AlreadyDirect,
    /// `/bridges` with nothing in it.
    NoBridgeLines,
    /// Bridge lines purple can't use.
    BadBridgeLines,
}

impl Notice {
    /// Wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::StillTrying => 0,
            Self::NoDirectAddress => 1,
            Self::AlreadyDirect => 2,
            Self::NoBridgeLines => 3,
            Self::BadBridgeLines => 4,
        }
    }

    /// The notice with wire code `code`.
    ///
    /// # Errors
    /// Fails on an unknown code.
    pub fn from_code(code: u8) -> io::Result<Self> {
        Ok(match code {
            0 => Self::StillTrying,
            1 => Self::NoDirectAddress,
            2 => Self::AlreadyDirect,
            3 => Self::NoBridgeLines,
            4 => Self::BadBridgeLines,
            _ => return Err(invalid("unknown notice")),
        })
    }

    /// What the user reads.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::StillTrying => {
                "purple is still trying Tor; /direct and /bridges come if every route fails"
            }
            Self::NoDirectAddress => "this store has no direct address configured",
            Self::AlreadyDirect => "already connected directly to the store",
            Self::NoBridgeLines => "no bridge lines in that",
            Self::BadBridgeLines => {
                "purple can't use those bridge lines: paste obfs4, snowflake or webtunnel lines, one type at a time"
            }
        }
    }
}

/// Messages between purple-data and purple-cloak.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TorCtlMsg {
    /// torctl to core: how the connection is going.
    Status(NetStatus),
    /// torctl to core: the user may go direct; ask the launcher for the relay.
    GoDirect,
    /// torctl to core: tell the user this.
    Notice(Notice),
    /// core to torctl: the user's answer to Blocked.
    Choose(NetChoice),
    /// core to torctl: the relay is up and purple-subspace uses it.
    DirectUp,
    /// core to torctl: the relay couldn't start.
    DirectFailed,
}

impl TorCtlMsg {
    /// Write as one frame.
    ///
    /// # Errors
    /// Fails if the bridge text is too long, or the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut out = Vec::new();
        match self {
            Self::Status(status) => {
                out.push(TAG_STATUS);
                out.extend_from_slice(&status.to_bytes());
            }
            Self::GoDirect => out.push(TAG_GO_DIRECT),
            Self::Notice(notice) => out.extend_from_slice(&[TAG_NOTICE, notice.code()]),
            Self::Choose(NetChoice::Direct) => out.extend_from_slice(&[TAG_CHOOSE, 0]),
            Self::Choose(NetChoice::Bridges(lines)) => {
                if lines.len() > MAX_BRIDGE_TEXT {
                    return Err(invalid("too much bridge text"));
                }
                out.extend_from_slice(&[TAG_CHOOSE, 1]);
                out.extend_from_slice(lines.as_bytes());
            }
            Self::DirectUp => out.push(TAG_DIRECT_UP),
            Self::DirectFailed => out.push(TAG_DIRECT_FAILED),
        }
        write_frame(w, &out, MAX_TORCTL_FRAME)
    }

    /// Read one message; `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error or a malformed message.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let Some(frame) = read_frame(r, MAX_TORCTL_FRAME)? else {
            return Ok(None);
        };
        Ok(Some(match frame.as_slice() {
            [TAG_STATUS, kind, route, percent] => {
                Self::Status(NetStatus::from_bytes([*kind, *route, *percent])?)
            }
            [TAG_GO_DIRECT] => Self::GoDirect,
            [TAG_NOTICE, code] => Self::Notice(Notice::from_code(*code)?),
            [TAG_CHOOSE, 0] => Self::Choose(NetChoice::Direct),
            [TAG_CHOOSE, 1, lines @ ..] => Self::Choose(NetChoice::Bridges(
                std::str::from_utf8(lines)
                    .map_err(|_| invalid("bridges aren't UTF-8"))?
                    .to_owned(),
            )),
            [TAG_DIRECT_UP] => Self::DirectUp,
            [TAG_DIRECT_FAILED] => Self::DirectFailed,
            _ => return Err(invalid("malformed purple-cloak message")),
        }))
    }
}

/// Messages between purple-data and the launcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherMsg {
    /// core to launcher: the user chose direct; start purple-transporter.
    StartRelay,
    /// launcher to core: purple-transporter's socket is up.
    RelayUp,
    /// launcher to core: purple-transporter couldn't start.
    RelayFailed,
}

impl LauncherMsg {
    /// Write as one frame.
    ///
    /// # Errors
    /// Fails if the write fails.
    pub fn write_to(self, w: &mut impl Write) -> io::Result<()> {
        let tag = match self {
            Self::StartRelay => TAG_START_RELAY,
            Self::RelayUp => TAG_RELAY_UP,
            Self::RelayFailed => TAG_RELAY_FAILED,
        };
        write_frame(w, &[tag], MAX_LAUNCHER_FRAME)
    }

    /// Read one message; `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error or a malformed message.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let Some(frame) = read_frame(r, MAX_LAUNCHER_FRAME)? else {
            return Ok(None);
        };
        Ok(Some(match frame.as_slice() {
            [TAG_START_RELAY] => Self::StartRelay,
            [TAG_RELAY_UP] => Self::RelayUp,
            [TAG_RELAY_FAILED] => Self::RelayFailed,
            _ => return Err(invalid("malformed launcher message")),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetChoice, NetStatus, Route};

    fn round<T>(
        msg: &T,
        write: fn(&T, &mut Vec<u8>) -> io::Result<()>,
        read: fn(&mut &[u8]) -> io::Result<Option<T>>,
    ) -> T {
        let mut frame = Vec::new();
        write(msg, &mut frame).unwrap();
        read(&mut &frame[..]).unwrap().unwrap()
    }

    #[test]
    fn torctl_messages_round_trip() {
        for msg in [
            TorCtlMsg::Status(NetStatus::Connecting {
                route: Route::Obfs4,
                percent: 40,
            }),
            TorCtlMsg::Status(NetStatus::Blocked),
            TorCtlMsg::GoDirect,
            TorCtlMsg::Notice(Notice::BadBridgeLines),
            TorCtlMsg::Choose(NetChoice::Direct),
            TorCtlMsg::Choose(NetChoice::Bridges(
                "obfs4 192.0.2.1:443 F cert=c iat-mode=0".into(),
            )),
            TorCtlMsg::DirectUp,
            TorCtlMsg::DirectFailed,
        ] {
            assert_eq!(
                round(&msg, TorCtlMsg::write_to, |r| TorCtlMsg::read_from(r)),
                msg
            );
        }
    }

    #[test]
    fn launcher_messages_round_trip() {
        for msg in [
            LauncherMsg::StartRelay,
            LauncherMsg::RelayUp,
            LauncherMsg::RelayFailed,
        ] {
            assert_eq!(
                round(&msg, |m, w| m.write_to(w), |r| LauncherMsg::read_from(r)),
                msg
            );
        }
    }

    #[test]
    fn garbage_is_refused() {
        let frame = |body: &[u8]| {
            let mut f = Vec::new();
            write_frame(&mut f, body, 64).unwrap();
            f
        };
        assert!(
            TorCtlMsg::read_from(&mut &frame(&[99])[..]).is_err(),
            "unknown tag"
        );
        assert!(
            TorCtlMsg::read_from(&mut &frame(&[3, 9])[..]).is_err(),
            "unknown notice"
        );
        assert!(
            TorCtlMsg::read_from(&mut &frame(&[2, 0])[..]).is_err(),
            "trailing bytes"
        );
        assert!(
            LauncherMsg::read_from(&mut &frame(&[1, 0])[..]).is_err(),
            "trailing bytes"
        );
        let long = TorCtlMsg::Choose(NetChoice::Bridges("a".repeat(MAX_BRIDGE_TEXT + 1)));
        assert!(long.write_to(&mut Vec::new()).is_err());
    }

    #[test]
    fn every_notice_has_text() {
        for n in [
            Notice::StillTrying,
            Notice::NoDirectAddress,
            Notice::AlreadyDirect,
            Notice::NoBridgeLines,
            Notice::BadBridgeLines,
        ] {
            assert!(!n.text().is_empty());
            assert_eq!(Notice::from_code(n.code()).unwrap(), n);
        }
    }
}
