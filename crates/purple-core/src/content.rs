//! What goes inside an encrypted message.
//!
//! Layout: version (1 byte), kind (1 byte), then the kind's fields.

use zeroize::Zeroizing;

use crate::queue::QueueSecret;
use crate::session::{Error, Result};

const VERSION: u8 = 1;
const KIND_HELLO: u8 = 1;
const KIND_TEXT: u8 = 2;
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
}

impl Content {
    /// Encode for encryption.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![VERSION]);
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
        }
        out
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
            _ => Err(Error::Malformed("unknown content kind")),
        }
    }
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
        .encode();
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
            let encoded = Content::Text(body.to_vec()).encode();
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
}
