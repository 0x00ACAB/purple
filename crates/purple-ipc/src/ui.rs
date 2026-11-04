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

/// The largest message is a name plus a body.
const MAX_UI_FRAME: usize = 1 + 2 + MAX_NAME_LEN + 2 + MAX_BODY_LEN;

const CMD_CREATE_INVITE: u8 = 1;
const CMD_ACCEPT_INVITE: u8 = 2;
const CMD_SEND: u8 = 3;

const EVENT_INVITE_CREATED: u8 = 1;
const EVENT_CONNECTED: u8 = 2;
const EVENT_MESSAGE: u8 = 3;
const EVENT_ERROR: u8 = 4;

/// What the user asked for, sent from `purple-ui` to `purple-core`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiCmd {
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

/// What happened, sent from `purple-core` to `purple-ui`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEvent {
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

impl UiCmd {
    /// Write as one frame.
    ///
    /// # Errors
    /// Fails if a field is too long, or the write fails.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        let mut out = Encoder::default();
        match self {
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
    }
}
