//! What goes inside an encrypted message.
//!
//! Layout: version (1 byte), kind (1 byte), then the kind's fields.

use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::queue::QueueSecret;
use crate::session::{Error, Result};

const VERSION: u8 = 1;
const KIND_HELLO: u8 = 1;
const KIND_TEXT: u8 = 2;
const KIND_GROUP_REQUEST: u8 = 3;
const KIND_GROUP_ACCEPT: u8 = 4;
const KIND_GROUP_WELCOME: u8 = 5;
const KIND_GROUP_LEAVE: u8 = 6;
const SECRET_LEN: usize = 32;

/// One message's contents.
#[derive(Debug)]
pub enum Content {
    /// First message after accepting an invite. Hands the inviter the secrets for both
    /// directions of the conversation.
    Hello {
        /// Secret for the accepter-to-inviter queue.
        to_inviter: QueueSecret,
        /// Secret for the inviter-to-accepter queue.
        to_accepter: QueueSecret,
    },
    /// A text message.
    Text(Vec<u8>),
    /// The creator asks this contact to join a group.
    GroupRequest {
        /// The group's name.
        group: String,
    },
    /// The contact agrees, sending a key package for the creator to add.
    GroupAccept {
        /// The group's name.
        group: String,
        /// The MLS key package.
        key_package: Vec<u8>,
    },
    /// The creator added this contact.
    GroupWelcome {
        /// The group's name.
        group: String,
        /// The MLS Welcome.
        welcome: Vec<u8>,
        /// The creator's names for members, by identity key.
        names: Vec<(Vec<u8>, String)>,
    },
    /// A member asks the creator to remove them.
    GroupLeave {
        /// The group's name.
        group: String,
    },
}

impl Content {
    /// Encode for encryption.
    ///
    /// # Errors
    /// Fails only on absurd lengths.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(vec![VERSION]);
        let mut w = Writer::default();
        match self {
            Self::Hello {
                to_inviter,
                to_accepter,
            } => {
                out.push(KIND_HELLO);
                out.extend_from_slice(to_inviter.as_bytes());
                out.extend_from_slice(to_accepter.as_bytes());
            }
            Self::Text(body) => {
                out.push(KIND_TEXT);
                out.extend_from_slice(body);
            }
            Self::GroupRequest { group } => {
                out.push(KIND_GROUP_REQUEST);
                w.bytes(group.as_bytes())?;
            }
            Self::GroupAccept { group, key_package } => {
                out.push(KIND_GROUP_ACCEPT);
                w.bytes(group.as_bytes())?;
                w.bytes(key_package)?;
            }
            Self::GroupWelcome {
                group,
                welcome,
                names,
            } => {
                out.push(KIND_GROUP_WELCOME);
                w.bytes(group.as_bytes())?;
                w.bytes(welcome)?;
                w.len(names.len())?;
                for (identity, name) in names {
                    w.bytes(identity)?;
                    w.bytes(name.as_bytes())?;
                }
            }
            Self::GroupLeave { group } => {
                out.push(KIND_GROUP_LEAVE);
                w.bytes(group.as_bytes())?;
            }
        }
        out.extend_from_slice(&w.finish());
        Ok(out)
    }

    /// Decode decrypted bytes.
    ///
    /// # Errors
    /// Fails on an unknown version or kind, or a Hello of the wrong length.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [version, kind, rest @ ..] = bytes else {
            return Err(Error::Malformed("content too short"));
        };
        if *version != VERSION {
            return Err(Error::Malformed("unknown content version"));
        }
        match *kind {
            KIND_HELLO => {
                let (to_inviter, rest) = rest
                    .split_first_chunk::<SECRET_LEN>()
                    .ok_or(Error::Malformed("hello too short"))?;
                let to_accepter: &[u8; SECRET_LEN] = rest
                    .try_into()
                    .map_err(|_| Error::Malformed("hello has the wrong length"))?;
                Ok(Self::Hello {
                    to_inviter: QueueSecret::from_bytes(Zeroizing::new(*to_inviter)),
                    to_accepter: QueueSecret::from_bytes(Zeroizing::new(*to_accepter)),
                })
            }
            KIND_TEXT => Ok(Self::Text(rest.to_vec())),
            KIND_GROUP_REQUEST | KIND_GROUP_ACCEPT | KIND_GROUP_WELCOME | KIND_GROUP_LEAVE => {
                decode_group(*kind, rest)
            }
            _ => Err(Error::Malformed("unknown content kind")),
        }
    }
}

/// The group control kinds, whose fields are in the snapshot codec's layout.
fn decode_group(kind: u8, fields: &[u8]) -> Result<Content> {
    let mut r = Reader::new(fields);
    let group = r.string()?;
    let content = match kind {
        KIND_GROUP_REQUEST => Content::GroupRequest { group },
        KIND_GROUP_ACCEPT => Content::GroupAccept {
            group,
            key_package: r.bytes()?.to_vec(),
        },
        KIND_GROUP_WELCOME => {
            let welcome = r.bytes()?.to_vec();
            let mut names = Vec::new();
            for _ in 0..r.len()? {
                names.push((r.bytes()?.to_vec(), r.string()?));
            }
            Content::GroupWelcome {
                group,
                welcome,
                names,
            }
        }
        _ => Content::GroupLeave { group },
    };
    r.finish()?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips() {
        let to_inviter = QueueSecret::random().unwrap();
        let to_accepter = QueueSecret::random().unwrap();
        let encoded = Content::Hello {
            to_inviter: to_inviter.clone(),
            to_accepter: to_accepter.clone(),
        }
        .encode()
        .unwrap();
        let Content::Hello {
            to_inviter: a,
            to_accepter: b,
        } = Content::decode(&encoded).unwrap()
        else {
            panic!("not a hello");
        };
        assert_eq!(a.as_bytes(), to_inviter.as_bytes());
        assert_eq!(b.as_bytes(), to_accepter.as_bytes());
    }

    #[test]
    fn text_round_trips_including_empty() {
        for body in [&b""[..], b"hello"] {
            let encoded = Content::Text(body.to_vec()).encode().unwrap();
            assert!(matches!(Content::decode(&encoded).unwrap(), Content::Text(t) if t == body));
        }
    }

    #[test]
    fn rejects_malformed_content() {
        assert!(Content::decode(&[]).is_err());
        assert!(Content::decode(&[VERSION]).is_err());
        assert!(Content::decode(&[2, KIND_TEXT]).is_err());
        assert!(Content::decode(&[VERSION, 99]).is_err());
        assert!(Content::decode(&[VERSION, KIND_HELLO, 0, 0]).is_err());
        let mut long_hello = vec![VERSION, KIND_HELLO];
        long_hello.extend_from_slice(&[0; 2 * SECRET_LEN + 1]);
        assert!(Content::decode(&long_hello).is_err());
    }

    #[test]
    fn group_control_messages_round_trip() {
        let all = [
            Content::GroupRequest {
                group: "team".into(),
            },
            Content::GroupAccept {
                group: "team".into(),
                key_package: vec![1, 2],
            },
            Content::GroupWelcome {
                group: "team".into(),
                welcome: vec![3],
                names: vec![(vec![4; 33], "bob".into())],
            },
            Content::GroupLeave {
                group: "team".into(),
            },
        ];
        for content in all {
            let encoded = content.encode().unwrap();
            assert_eq!(
                format!("{:?}", Content::decode(&encoded).unwrap()),
                format!("{content:?}")
            );
        }
        assert!(Content::decode(&[VERSION, KIND_GROUP_REQUEST]).is_err());
        let mut trailing = Content::GroupLeave {
            group: "team".into(),
        }
        .encode()
        .unwrap()
        .to_vec();
        trailing.push(0);
        assert!(Content::decode(&trailing).is_err());
    }
}
