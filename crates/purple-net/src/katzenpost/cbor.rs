//! The subset of CBOR (RFC 8949) that kpclientd's thin-client protocol uses.
//!
//! The daemon runs in its own sandbox and isn't trusted with anything secret, but it can
//! still send garbage, so decoding is strict: every declared length must fit in the input,
//! nesting stops at [`MAX_DEPTH`], and nothing is allocated beyond what the input could
//! hold. Indefinite lengths are rejected; the daemon (Go, fxamacker/cbor) never sends them.
//! Tags are read and dropped.

use std::io;

/// Deepest nesting accepted. The protocol's messages are three levels deep at most.
const MAX_DEPTH: usize = 16;

const UINT: u8 = 0x00;
const NEGATIVE: u8 = 0x20;
const BYTES: u8 = 0x40;
const TEXT: u8 = 0x60;
const ARRAY: u8 = 0x80;
const MAP: u8 = 0xa0;
const TAG: u8 = 0xc0;
const SIMPLE: u8 = 0xe0;
const MAJOR_MASK: u8 = 0xe0;
const INFO_MASK: u8 = 0x1f;
/// Additional information saying a 1-, 2-, 4- or 8-byte argument follows.
const ARG_1: u8 = 0x18;
const ARG_2: u8 = 0x19;
const ARG_4: u8 = 0x1a;
const ARG_8: u8 = 0x1b;

const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;

/// A decoded CBOR item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Uint(u64),
    /// The integer -1 - n.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Bool(bool),
    /// `null` or `undefined`.
    Null,
    /// A float or other simple value, as its encoded bytes. No field purple reads uses them.
    Simple(Vec<u8>),
}

impl Value {
    /// A map with text keys, the shape of every protocol message.
    pub(crate) fn map<'a>(entries: impl IntoIterator<Item = (&'a str, Self)>) -> Self {
        Self::Map(
            entries
                .into_iter()
                .map(|(key, value)| (Self::Text(key.to_owned()), value))
                .collect(),
        )
    }

    /// The value under text key `key`, if this is a map that has one.
    #[must_use]
    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(k, _)| matches!(k, Self::Text(text) if text == key))
            .map(|(_, value)| value)
    }

    /// The name and body of a protocol message: the one entry of a map that isn't null.
    /// The daemon sends every possible field of its response type, all null but one.
    #[must_use]
    pub(crate) fn message(&self) -> Option<(&str, &Self)> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries.iter().find_map(|(key, value)| match (key, value) {
            (_, Self::Null) => None,
            (Self::Text(name), body) => Some((name.as_str(), body)),
            _ => None,
        })
    }

    #[must_use]
    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        if let Self::Bytes(bytes) = self {
            Some(bytes)
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) const fn as_u64(&self) -> Option<u64> {
        if let Self::Uint(n) = self {
            Some(*n)
        } else {
            None
        }
    }

    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Uint(n) => head(out, UINT, *n),
            Self::Negative(n) => head(out, NEGATIVE, *n),
            Self::Bytes(bytes) => {
                head(out, BYTES, length(bytes.len()));
                out.extend_from_slice(bytes);
            }
            Self::Text(text) => {
                head(out, TEXT, length(text.len()));
                out.extend_from_slice(text.as_bytes());
            }
            Self::Array(items) => {
                head(out, ARRAY, length(items.len()));
                for item in items {
                    item.encode_into(out);
                }
            }
            Self::Map(entries) => {
                head(out, MAP, length(entries.len()));
                for (key, value) in entries {
                    key.encode_into(out);
                    value.encode_into(out);
                }
            }
            Self::Bool(false) => out.push(FALSE),
            Self::Bool(true) => out.push(TRUE),
            Self::Null => out.push(NULL),
            Self::Simple(bytes) => out.extend_from_slice(bytes),
        }
    }

    /// Decode exactly one item that fills `bytes`.
    ///
    /// # Errors
    /// Fails on anything malformed, truncated, too deep, or followed by trailing bytes.
    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        let mut reader = Reader { rest: bytes };
        let value = reader.value(0)?;
        if !reader.rest.is_empty() {
            return Err(invalid("trailing bytes after the CBOR item"));
        }
        Ok(value)
    }
}

/// An item's head: major type and argument, in the shortest form.
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    match (u8::try_from(n), u16::try_from(n), u32::try_from(n)) {
        (Ok(small), _, _) if small < ARG_1 => out.push(major | small),
        (Ok(byte), _, _) => out.extend([major | ARG_1, byte]),
        (_, Ok(short), _) => {
            out.push(major | ARG_2);
            out.extend(short.to_be_bytes());
        }
        (_, _, Ok(word)) => {
            out.push(major | ARG_4);
            out.extend(word.to_be_bytes());
        }
        _ => {
            out.push(major | ARG_8);
            out.extend(n.to_be_bytes());
        }
    }
}

fn length(len: usize) -> u64 {
    // usize is at most 64 bits on every target Rust supports.
    u64::try_from(len).unwrap_or(u64::MAX)
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> io::Result<u8> {
        let (&byte, rest) = self.rest.split_first().ok_or_else(truncated)?;
        self.rest = rest;
        Ok(byte)
    }

    fn chunk<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let (chunk, rest) = self.rest.split_first_chunk::<N>().ok_or_else(truncated)?;
        self.rest = rest;
        Ok(*chunk)
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let (taken, rest) = self.rest.split_at_checked(len).ok_or_else(truncated)?;
        self.rest = rest;
        Ok(taken)
    }

    fn argument(&mut self, info: u8) -> io::Result<u64> {
        match info {
            0..ARG_1 => Ok(u64::from(info)),
            ARG_1 => Ok(u64::from(self.byte()?)),
            ARG_2 => Ok(u64::from(u16::from_be_bytes(self.chunk()?))),
            ARG_4 => Ok(u64::from(u32::from_be_bytes(self.chunk()?))),
            ARG_8 => Ok(u64::from_be_bytes(self.chunk()?)),
            31 => Err(invalid("indefinite-length CBOR isn't supported")),
            _ => Err(invalid("reserved CBOR additional information")),
        }
    }

    /// A length that must fit in the rest of the input, at `min_size` bytes per element.
    fn count(&mut self, info: u8, min_size: usize) -> io::Result<usize> {
        let count = usize::try_from(self.argument(info)?).map_err(|_| truncated())?;
        if count.saturating_mul(min_size) > self.rest.len() {
            return Err(truncated());
        }
        Ok(count)
    }

    fn value(&mut self, depth: usize) -> io::Result<Value> {
        if depth > MAX_DEPTH {
            return Err(invalid("CBOR nested too deeply"));
        }
        let start = self.rest;
        let initial = self.byte()?;
        let info = initial & INFO_MASK;
        let inner = depth.saturating_add(1);
        match initial & MAJOR_MASK {
            UINT => Ok(Value::Uint(self.argument(info)?)),
            NEGATIVE => Ok(Value::Negative(self.argument(info)?)),
            BYTES => {
                let len = self.count(info, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            TEXT => {
                let len = self.count(info, 1)?;
                let text = std::str::from_utf8(self.take(len)?)
                    .map_err(|_| invalid("CBOR text isn't UTF-8"))?;
                Ok(Value::Text(text.to_owned()))
            }
            ARRAY => {
                let count = self.count(info, 1)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(inner)?);
                }
                Ok(Value::Array(items))
            }
            MAP => {
                let count = self.count(info, 2)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let key = self.value(inner)?;
                    entries.push((key, self.value(inner)?));
                }
                Ok(Value::Map(entries))
            }
            TAG => {
                self.argument(info)?;
                self.value(inner)
            }
            SIMPLE => match initial {
                FALSE => Ok(Value::Bool(false)),
                TRUE => Ok(Value::Bool(true)),
                NULL | 0xf7 => Ok(Value::Null),
                _ => {
                    // Floats are the argument's bytes; simple values 0..=19 and 32.. too.
                    // A break (0xff) has info 31 and is rejected as indefinite.
                    self.argument(info)?;
                    let used = start.len().saturating_sub(self.rest.len());
                    let bytes = start.get(..used).ok_or_else(truncated)?;
                    Ok(Value::Simple(bytes.to_vec()))
                }
            },
            _ => Err(invalid("unknown CBOR major type")),
        }
    }
}

fn truncated() -> io::Error {
    invalid("CBOR item runs past the end of its frame")
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, RngCore};

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_rfc_8949_examples() {
        let cases = [
            ("00", Value::Uint(0)),
            ("17", Value::Uint(23)),
            ("1818", Value::Uint(24)),
            ("1903e8", Value::Uint(1000)),
            ("1a000f4240", Value::Uint(1_000_000)),
            ("1b000000e8d4a51000", Value::Uint(1_000_000_000_000)),
            ("1bffffffffffffffff", Value::Uint(u64::MAX)),
            ("20", Value::Negative(0)),
            ("3863", Value::Negative(99)),
            ("4401020304", Value::Bytes(vec![1, 2, 3, 4])),
            ("6449455446", Value::Text("IETF".into())),
            ("f4", Value::Bool(false)),
            ("f5", Value::Bool(true)),
            ("f6", Value::Null),
            (
                "83010203",
                Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]),
            ),
            (
                "a26161016162820203",
                Value::map([
                    ("a", Value::Uint(1)),
                    ("b", Value::Array(vec![Value::Uint(2), Value::Uint(3)])),
                ]),
            ),
        ];
        for (encoded, value) in cases {
            assert_eq!(Value::decode(&hex(encoded)).unwrap(), value, "{encoded}");
            assert_eq!(value.encode(), hex(encoded), "{encoded}");
        }
    }

    #[test]
    fn floats_and_tags_decode_without_being_understood() {
        let float = hex("fb3ff199999999999a"); // 1.1
        assert_eq!(Value::decode(&float).unwrap(), Value::Simple(float.clone()));
        assert_eq!(Value::decode(&float).unwrap().encode(), float);
        // Tag 1 (epoch time) around 1363896240.
        assert_eq!(
            Value::decode(&hex("c11a514b67b0")).unwrap(),
            Value::Uint(1_363_896_240)
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",                   // nothing
            "18",                 // argument missing
            "4401",               // bytes shorter than declared
            "5bffffffffffffffff", // huge length
            "9bffffffffffffffff", // huge array
            "5f",                 // indefinite bytes
            "ff",                 // stray break
            "1c",                 // reserved info
            "62c328",             // invalid UTF-8
            "0000",               // trailing bytes
            "a1",                 // map with no entries present
        ] {
            assert!(Value::decode(&hex(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_deep_nesting() {
        let fine = [vec![0x81; MAX_DEPTH], vec![0x00]].concat();
        assert!(Value::decode(&fine).is_ok());
        let deep = [vec![0x81; MAX_DEPTH + 1], vec![0x00]].concat();
        assert!(Value::decode(&deep).is_err());
    }

    #[test]
    fn random_input_never_panics() {
        let mut rng = rand::rng();
        for _ in 0..20_000 {
            let mut bytes = vec![0u8; rng.random_range(0..64)];
            rng.fill_bytes(&mut bytes);
            if let Ok(value) = Value::decode(&bytes) {
                // Whatever decodes re-decodes to itself.
                assert_eq!(Value::decode(&value.encode()).unwrap(), value);
            }
        }
    }

    #[test]
    fn looks_up_text_keys() {
        let msg = Value::map([
            ("other_reply", Value::Null),
            ("reply", Value::map([("code", Value::Uint(7))])),
            ("third_reply", Value::Null),
        ]);
        let (name, reply) = msg.message().unwrap();
        assert_eq!(name, "reply");
        assert_eq!(reply.get("code").and_then(Value::as_u64), Some(7));
        assert!(reply.get("missing").is_none());
        assert!(Value::Uint(1).get("code").is_none());
    }
}
