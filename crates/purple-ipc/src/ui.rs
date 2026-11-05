//! Messages between `purple-ui` and `purple-core`.
//!
//! Layout: a tag byte, then the message's strings in order, each as UTF-8 with a u16 BE
//! length prefix, then nothing. Every string has a maximum length, checked on both ends.

use std::io::{self, Read, Write};

use crate::{invalid, read_frame, write_frame};

/// Longest contact name, in bytes.
pub const MAX_NAME_LEN: usize = 64;
/// Longest message body, in bytes.
pub const MAX_BODY_LEN: usize = 16 * 1024;
/// Longest invite string, in bytes.
pub const MAX_INVITE_LEN: usize = 256;
/// Longest error text, in bytes.
pub const MAX_ERROR_LEN: usize = 512;
/// Longest passphrase, in bytes.
pub const MAX_PASSPHRASE_LEN: usize = 1024;
/// Longest recovery code text, in bytes.
pub const MAX_RECOVERY_LEN: usize = 64;

/// The largest message is a name plus a body.
const MAX_UI_FRAME: usize = 1 + 2 + MAX_NAME_LEN + 2 + MAX_BODY_LEN;

const CMD_CREATE_INVITE: u8 = 1;
const CMD_ACCEPT_INVITE: u8 = 2;
const CMD_SEND: u8 = 3;
const CMD_UNLOCK: u8 = 4;
const CMD_CHANGE_PASSPHRASE: u8 = 5;
const CMD_ENROLL_TPM: u8 = 6;

const EVENT_INVITE_CREATED: u8 = 1;
const EVENT_CONNECTED: u8 = 2;
const EVENT_MESSAGE: u8 = 3;
const EVENT_ERROR: u8 = 4;
const EVENT_NEED_PASSPHRASE: u8 = 5;
const EVENT_UNLOCKED: u8 = 6;
const EVENT_SENT: u8 = 7;
const EVENT_PASSPHRASE_CHANGED: u8 = 8;
const EVENT_TPM_ENROLLED: u8 = 9;
const EVENT_RECOVERY_UNLOCKED: u8 = 10;

/// What the user asked for, sent from `purple-ui` to `purple-core`.
#[derive(Clone, PartialEq, Eq)]
pub enum UiCmd {
    /// Unlock the vault, or create it if [`UiEvent::NeedPassphrase`] said it's new.
    Unlock {
        /// The passphrase as typed.
        passphrase: String,
    },
    /// Replace the vault passphrase.
    ChangePassphrase {
        /// The current passphrase.
        old: String,
        /// The new passphrase.
        new: String,
    },
    /// Seal the vault to the TPM.
    EnrollTpm {
        /// The current passphrase, which stays the passphrase.
        passphrase: String,
    },
    /// Create an invite for a contact to be known as `contact`.
    CreateInvite {
        /// Name for the new contact.
        contact: String,
    },
    /// Accept an invite string from a contact to be known as `contact`.
    AcceptInvite {
        /// Name for the new contact.
        contact: String,
        /// The invite string as pasted.
        invite: String,
    },
    /// Send a text message.
    Send {
        /// Recipient.
        contact: String,
        /// Message text.
        body: String,
    },
}

/// Debug without the passphrase.
impl std::fmt::Debug for UiCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlock { .. } => f.write_str("Unlock { .. }"),
            Self::ChangePassphrase { .. } => f.write_str("ChangePassphrase { .. }"),
            Self::EnrollTpm { .. } => f.write_str("EnrollTpm { .. }"),
            Self::CreateInvite { contact } => f
                .debug_struct("CreateInvite")
                .field("contact", contact)
                .finish(),
            Self::AcceptInvite { contact, .. } => f
                .debug_struct("AcceptInvite")
                .field("contact", contact)
                .finish_non_exhaustive(),
            Self::Send { contact, .. } => f
                .debug_struct("Send")
                .field("contact", contact)
                .finish_non_exhaustive(),
        }
    }
}

/// What happened, sent from `purple-core` to `purple-ui`.
#[derive(Clone, PartialEq, Eq)]
pub enum UiEvent {
    /// The vault is locked. `new` is true when there's no vault yet and the passphrase
    /// will create one.
    NeedPassphrase {
        /// Whether unlocking will create a new vault.
        new: bool,
    },
    /// The vault is open. Saved contacts and history follow as ordinary events.
    Unlocked,
    /// The passphrase was changed.
    PassphraseChanged,
    /// The vault is now sealed to the TPM. The recovery code is shown this once.
    TpmEnrolled {
        /// The code that opens the vault without the TPM.
        recovery_code: String,
    },
    /// The vault was opened with the recovery code, so a new passphrase should be set.
    RecoveryUnlocked,
    /// A message this user sent earlier, replayed from history.
    Sent {
        /// Recipient.
        to: String,
        /// Message text.
        body: String,
    },
    /// An invite is ready to show.
    InviteCreated {
        /// Contact it's for.
        contact: String,
        /// The invite string.
        invite: String,
    },
    /// A contact finished connecting.
    Connected {
        /// The contact.
        contact: String,
    },
    /// A message arrived.
    Message {
        /// Sender.
        from: String,
        /// Message text.
        body: String,
    },
    /// A command failed, or something went wrong in the background.
    Error {
        /// What went wrong.
        message: String,
    },
}

/// Debug without the recovery code; message text is shown, as the UI shows it anyway.
impl std::fmt::Debug for UiEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedPassphrase { new } => {
                f.debug_struct("NeedPassphrase").field("new", new).finish()
            }
            Self::Unlocked => f.write_str("Unlocked"),
            Self::PassphraseChanged => f.write_str("PassphraseChanged"),
            Self::TpmEnrolled { .. } => f.write_str("TpmEnrolled { .. }"),
            Self::RecoveryUnlocked => f.write_str("RecoveryUnlocked"),
            Self::Sent { to, body } => f
                .debug_struct("Sent")
                .field("to", to)
                .field("body", body)
                .finish(),
            Self::InviteCreated { contact, invite } => f
                .debug_struct("InviteCreated")
                .field("contact", contact)
                .field("invite", invite)
                .finish(),
            Self::Connected { contact } => f
                .debug_struct("Connected")
                .field("contact", contact)
                .finish(),
            Self::Message { from, body } => f
                .debug_struct("Message")
                .field("from", from)
                .field("body", body)
                .finish(),
            Self::Error { message } => f.debug_struct("Error").field("message", message).finish(),
        }
    }
}

impl UiCmd {
    /// Write as one frame.
    ///
    /// # Errors
    /// Fails if a field is too long, or the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut out = Encoder::default();
        match self {
            Self::Unlock { passphrase } => {
                out.tag(CMD_UNLOCK);
                out.str(passphrase, MAX_PASSPHRASE_LEN)?;
            }
            Self::ChangePassphrase { old, new } => {
                out.tag(CMD_CHANGE_PASSPHRASE);
                out.str(old, MAX_PASSPHRASE_LEN)?;
                out.str(new, MAX_PASSPHRASE_LEN)?;
            }
            Self::EnrollTpm { passphrase } => {
                out.tag(CMD_ENROLL_TPM);
                out.str(passphrase, MAX_PASSPHRASE_LEN)?;
            }
            Self::CreateInvite { contact } => {
                out.tag(CMD_CREATE_INVITE);
                out.str(contact, MAX_NAME_LEN)?;
            }
            Self::AcceptInvite { contact, invite } => {
                out.tag(CMD_ACCEPT_INVITE);
                out.str(contact, MAX_NAME_LEN)?;
                out.str(invite, MAX_INVITE_LEN)?;
            }
            Self::Send { contact, body } => {
                out.tag(CMD_SEND);
                out.str(contact, MAX_NAME_LEN)?;
                out.str(body, MAX_BODY_LEN)?;
            }
        }
        write_frame(w, &out.0, MAX_UI_FRAME)
    }

    /// Read one command. Returns `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error or a malformed command.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let Some(frame) = read_frame(r, MAX_UI_FRAME)? else {
            return Ok(None);
        };
        let mut d = Decoder(&frame);
        let cmd = match d.tag()? {
            CMD_UNLOCK => Self::Unlock {
                passphrase: d.str(MAX_PASSPHRASE_LEN)?,
            },
            CMD_CHANGE_PASSPHRASE => Self::ChangePassphrase {
                old: d.str(MAX_PASSPHRASE_LEN)?,
                new: d.str(MAX_PASSPHRASE_LEN)?,
            },
            CMD_ENROLL_TPM => Self::EnrollTpm {
                passphrase: d.str(MAX_PASSPHRASE_LEN)?,
            },
            CMD_CREATE_INVITE => Self::CreateInvite {
                contact: d.str(MAX_NAME_LEN)?,
            },
            CMD_ACCEPT_INVITE => Self::AcceptInvite {
                contact: d.str(MAX_NAME_LEN)?,
                invite: d.str(MAX_INVITE_LEN)?,
            },
            CMD_SEND => Self::Send {
                contact: d.str(MAX_NAME_LEN)?,
                body: d.str(MAX_BODY_LEN)?,
            },
            _ => return Err(invalid("unknown UI command")),
        };
        d.finish()?;
        Ok(Some(cmd))
    }
}

impl UiEvent {
    /// Write as one frame.
    ///
    /// # Errors
    /// Fails if a field is too long, or the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut out = Encoder::default();
        match self {
            Self::NeedPassphrase { new } => {
                out.tag(EVENT_NEED_PASSPHRASE);
                out.tag(u8::from(*new));
            }
            Self::Unlocked => out.tag(EVENT_UNLOCKED),
            Self::PassphraseChanged => out.tag(EVENT_PASSPHRASE_CHANGED),
            Self::TpmEnrolled { recovery_code } => {
                out.tag(EVENT_TPM_ENROLLED);
                out.str(recovery_code, MAX_RECOVERY_LEN)?;
            }
            Self::RecoveryUnlocked => out.tag(EVENT_RECOVERY_UNLOCKED),
            Self::Sent { to, body } => {
                out.tag(EVENT_SENT);
                out.str(to, MAX_NAME_LEN)?;
                out.str(body, MAX_BODY_LEN)?;
            }
            Self::InviteCreated { contact, invite } => {
                out.tag(EVENT_INVITE_CREATED);
                out.str(contact, MAX_NAME_LEN)?;
                out.str(invite, MAX_INVITE_LEN)?;
            }
            Self::Connected { contact } => {
                out.tag(EVENT_CONNECTED);
                out.str(contact, MAX_NAME_LEN)?;
            }
            Self::Message { from, body } => {
                out.tag(EVENT_MESSAGE);
                out.str(from, MAX_NAME_LEN)?;
                out.str(body, MAX_BODY_LEN)?;
            }
            Self::Error { message } => {
                out.tag(EVENT_ERROR);
                out.str(message, MAX_ERROR_LEN)?;
            }
        }
        write_frame(w, &out.0, MAX_UI_FRAME)
    }

    /// Read one event. Returns `None` on a clean EOF between frames.
    ///
    /// # Errors
    /// Fails on a read error or a malformed event.
    pub fn read_from(r: &mut impl Read) -> io::Result<Option<Self>> {
        let Some(frame) = read_frame(r, MAX_UI_FRAME)? else {
            return Ok(None);
        };
        let mut d = Decoder(&frame);
        let event = match d.tag()? {
            EVENT_NEED_PASSPHRASE => Self::NeedPassphrase {
                new: match d.tag()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid("invalid flag")),
                },
            },
            EVENT_UNLOCKED => Self::Unlocked,
            EVENT_PASSPHRASE_CHANGED => Self::PassphraseChanged,
            EVENT_TPM_ENROLLED => Self::TpmEnrolled {
                recovery_code: d.str(MAX_RECOVERY_LEN)?,
            },
            EVENT_RECOVERY_UNLOCKED => Self::RecoveryUnlocked,
            EVENT_SENT => Self::Sent {
                to: d.str(MAX_NAME_LEN)?,
                body: d.str(MAX_BODY_LEN)?,
            },
            EVENT_INVITE_CREATED => Self::InviteCreated {
                contact: d.str(MAX_NAME_LEN)?,
                invite: d.str(MAX_INVITE_LEN)?,
            },
            EVENT_CONNECTED => Self::Connected {
                contact: d.str(MAX_NAME_LEN)?,
            },
            EVENT_MESSAGE => Self::Message {
                from: d.str(MAX_NAME_LEN)?,
                body: d.str(MAX_BODY_LEN)?,
            },
            EVENT_ERROR => Self::Error {
                message: d.str(MAX_ERROR_LEN)?,
            },
            _ => return Err(invalid("unknown UI event")),
        };
        d.finish()?;
        Ok(Some(event))
    }
}

#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn tag(&mut self, tag: u8) {
        self.0.push(tag);
    }

    fn str(&mut self, s: &str, max: usize) -> io::Result<()> {
        if s.len() > max {
            return Err(invalid("string too long"));
        }
        let len = u16::try_from(s.len()).map_err(|_| invalid("string too long"))?;
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

struct Decoder<'a>(&'a [u8]);

impl Decoder<'_> {
    fn tag(&mut self) -> io::Result<u8> {
        let (&tag, rest) = self
            .0
            .split_first()
            .ok_or_else(|| invalid("empty message"))?;
        self.0 = rest;
        Ok(tag)
    }

    fn str(&mut self, max: usize) -> io::Result<String> {
        let (len, rest) = self
            .0
            .split_first_chunk::<2>()
            .ok_or_else(|| invalid("truncated"))?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len > max {
            return Err(invalid("string too long"));
        }
        let (bytes, rest) = rest
            .split_at_checked(len)
            .ok_or_else(|| invalid("truncated"))?;
        self.0 = rest;
        String::from_utf8(bytes.to_vec()).map_err(|_| invalid("string is not UTF-8"))
    }

    fn finish(&self) -> io::Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(invalid("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> String {
        text.to_owned()
    }

    #[test]
    fn commands_and_events_round_trip() {
        let cmds = [
            UiCmd::Unlock {
                passphrase: s("correct horse"),
            },
            UiCmd::ChangePassphrase {
                old: s("correct horse"),
                new: s("battery staple"),
            },
            UiCmd::EnrollTpm {
                passphrase: s("correct horse"),
            },
            UiCmd::CreateInvite {
                contact: s("alice"),
            },
            UiCmd::AcceptInvite {
                contact: s("bob"),
                invite: s("purple1abc"),
            },
            UiCmd::Send {
                contact: s("bob"),
                body: s("hi 🙂"),
            },
            UiCmd::Send {
                contact: s("bob"),
                body: "x".repeat(MAX_BODY_LEN),
            },
        ];
        let events = [
            UiEvent::NeedPassphrase { new: true },
            UiEvent::NeedPassphrase { new: false },
            UiEvent::Unlocked,
            UiEvent::PassphraseChanged,
            UiEvent::TpmEnrolled {
                recovery_code: s("AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA"),
            },
            UiEvent::RecoveryUnlocked,
            UiEvent::Sent {
                to: s("bob"),
                body: s("earlier"),
            },
            UiEvent::InviteCreated {
                contact: s("alice"),
                invite: s("purple1abc"),
            },
            UiEvent::Connected {
                contact: s("alice"),
            },
            UiEvent::Message {
                from: s("alice"),
                body: s(""),
            },
            UiEvent::Error { message: s("nope") },
        ];
        let mut cmd_buf = Vec::new();
        for cmd in &cmds {
            cmd.write_to(&mut cmd_buf).unwrap();
        }
        let mut cmd_reader = &cmd_buf[..];
        for cmd in &cmds {
            assert_eq!(
                UiCmd::read_from(&mut cmd_reader).unwrap().as_ref(),
                Some(cmd)
            );
        }
        assert_eq!(UiCmd::read_from(&mut cmd_reader).unwrap(), None);

        let mut event_buf = Vec::new();
        for event in &events {
            event.write_to(&mut event_buf).unwrap();
        }
        let mut event_reader = &event_buf[..];
        for event in &events {
            assert_eq!(
                UiEvent::read_from(&mut event_reader).unwrap().as_ref(),
                Some(event)
            );
        }
    }

    #[test]
    fn debug_never_shows_the_passphrase() {
        let cmd = UiCmd::Unlock {
            passphrase: s("hunter22"),
        };
        assert!(!format!("{cmd:?}").contains("hunter22"));
        let change = UiCmd::ChangePassphrase {
            old: s("hunter22"),
            new: s("hunter33"),
        };
        let shown = format!("{change:?}");
        assert!(!shown.contains("hunter22") && !shown.contains("hunter33"));
    }

    #[test]
    fn rejects_oversized_fields_on_write() {
        let long_name = UiCmd::CreateInvite {
            contact: "x".repeat(MAX_NAME_LEN + 1),
        };
        assert!(long_name.write_to(&mut Vec::new()).is_err());
        let long_body = UiCmd::Send {
            contact: s("a"),
            body: "x".repeat(MAX_BODY_LEN + 1),
        };
        assert!(long_body.write_to(&mut Vec::new()).is_err());
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, body, MAX_UI_FRAME).unwrap();
        out
    }

    #[test]
    fn rejects_malformed_frames() {
        // Unknown tag, truncated string, trailing bytes, invalid UTF-8, oversized name.
        let long_len = u16::try_from(MAX_NAME_LEN + 1).unwrap().to_be_bytes();
        let mut oversized = vec![CMD_CREATE_INVITE, long_len[0], long_len[1]];
        oversized.extend(std::iter::repeat_n(b'x', MAX_NAME_LEN + 1));
        for body in [
            vec![99],
            vec![CMD_CREATE_INVITE, 0, 5, b'a'],
            vec![CMD_CREATE_INVITE, 0, 1, b'a', 0],
            vec![CMD_CREATE_INVITE, 0, 1, 0xFF],
            oversized,
        ] {
            assert!(
                UiCmd::read_from(&mut &frame(&body)[..]).is_err(),
                "{body:?}"
            );
        }
        assert!(UiEvent::read_from(&mut &frame(&[99])[..]).is_err());
        assert!(UiEvent::read_from(&mut &frame(&[EVENT_NEED_PASSPHRASE, 2])[..]).is_err());
        assert!(UiEvent::read_from(&mut &frame(&[EVENT_UNLOCKED, 0])[..]).is_err());
    }
}
