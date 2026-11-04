//! A tiny binary codec for snapshots: u8/u32/u64 big-endian, and byte strings with a u32
//! length prefix. The reader rejects truncated input and, via [`Reader::finish`], trailing
//! bytes.

use zeroize::Zeroizing;

use crate::session::{Error, Result};

/// Builds a snapshot. Its buffer is zeroed when dropped, since snapshots hold keys.
#[derive(Default)]
pub(crate) struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<()> {
        self.len(value.len())?;
        self.0.extend_from_slice(value);
        Ok(())
    }

    /// A count of items that follow.
    pub(crate) fn len(&mut self, len: usize) -> Result<()> {
        self.u32(u32::try_from(len).map_err(|_| Error::Malformed("snapshot field too long"))?);
        Ok(())
    }

    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Reads a snapshot front to back.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(Error::Malformed("snapshot truncated"))?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.take()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    /// A count written by [`Writer::len`].
    pub(crate) fn len(&mut self) -> Result<usize> {
        usize::try_from(self.u32()?).map_err(|_| Error::Malformed("snapshot length too large"))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.len()?;
        let (head, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(Error::Malformed("snapshot truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    /// Exactly `len` raw bytes.
    pub(crate) fn raw(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(len)
            .ok_or(Error::Malformed("snapshot truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    /// Everything not read yet.
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn string(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| Error::Malformed("snapshot string is not UTF-8"))
    }

    pub(crate) const fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes in snapshot"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_truncation_and_trailing_bytes() {
        let mut w = Writer::default();
        w.u8(1);
        w.u32(2);
        w.u64(3);
        w.bytes(b"four").unwrap();
        let bytes = w.finish();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u32().unwrap(), 2);
        assert_eq!(r.u64().unwrap(), 3);
        assert_eq!(r.string().unwrap(), "four");
        r.finish().unwrap();

        let mut short = Reader::new(&bytes[..bytes.len() - 1]);
        short.take::<13>().unwrap();
        assert!(short.bytes().is_err());

        let mut padded = bytes.to_vec();
        padded.push(0);
        let mut trailing = Reader::new(&padded);
        trailing.take::<17>().unwrap();
        assert!(trailing.finish().is_err());
    }
}
