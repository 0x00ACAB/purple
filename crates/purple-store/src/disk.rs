//! Boxes on disk.
//!
//! Each record is fixed-size: when it was stored (seconds since the epoch),
//! the box address, and the packet. Records go into one append-only segment file per hour,
//! so expiry and the size cap delete whole files. The index of addresses lives in memory
//! and is rebuilt from the segments on start.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use purple_ipc::{PACKET_LEN, Packet};
use purple_net::{BoxAddr, Boxes};

/// Bytes per record: stored-at, address, packet.
pub const RECORD_LEN: usize = 8 + 32 + PACKET_LEN;
const SEGMENT_SECS: u64 = 3600;
const PREFIX: &str = "segment-";

/// How long boxes last and how much disk they may use.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Boxes older than this read as empty and may be written again.
    pub retention_secs: u64,
    /// Above this, the oldest segments are deleted.
    pub max_bytes: u64,
}

/// Seven days, 50 GB.
pub const DEFAULT_LIMITS: Limits = Limits {
    retention_secs: 7 * 24 * 3600,
    max_bytes: 50 * 1024 * 1024 * 1024,
};

#[derive(Debug)]
struct Segment {
    file: File,
    len: u64,
    addrs: Vec<BoxAddr>,
}

/// Write-once boxes in segment files under one directory.
#[derive(Debug)]
pub struct DiskStore {
    dir: PathBuf,
    limits: Limits,
    /// Address to (segment id, offset, stored at).
    index: HashMap<BoxAddr, (u64, u64, u64)>,
    segments: BTreeMap<u64, Segment>,
}

impl DiskStore {
    /// Open the store in `dir`, reading every segment. A partial record at the end of a
    /// segment (a crash mid-write) is cut off.
    ///
    /// # Errors
    /// Fails if the directory or a segment can't be read.
    pub fn open(dir: &Path, limits: Limits, now: u64) -> io::Result<Self> {
        let mut store = Self {
            dir: dir.to_path_buf(),
            limits,
            index: HashMap::new(),
            segments: BTreeMap::new(),
        };
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(id) = segment_id(&path) else {
                continue;
            };
            store.load(id, &path)?;
        }
        store.trim(now)?;
        Ok(store)
    }

    fn load(&mut self, id: u64, path: &Path) -> io::Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let whole = file
            .metadata()?
            .len()
            .checked_div(record_len())
            .unwrap_or(0);
        let len = whole.saturating_mul(record_len());
        file.set_len(len)?;
        let mut reader = io::BufReader::new(&file);
        let mut record = [0u8; RECORD_LEN];
        let mut addrs = Vec::new();
        for n in 0..whole {
            reader.read_exact(&mut record)?;
            let (at, addr) = header(&record)?;
            self.index
                .insert(addr, (id, n.saturating_mul(record_len()), at));
            addrs.push(addr);
        }
        self.segments.insert(id, Segment { file, len, addrs });
        Ok(())
    }

    /// Store `packet` at `addr` unless a live box is already there. Returns whether it was
    /// stored.
    ///
    /// # Errors
    /// Fails if the disk write fails.
    pub fn put(&mut self, addr: BoxAddr, packet: &Packet, now: u64) -> io::Result<bool> {
        self.trim(now)?;
        if self.live(&addr, now).is_some() {
            return Ok(false);
        }
        let id = now / SEGMENT_SECS;
        let segment = match self.segments.entry(id) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(self.dir.join(format!("{PREFIX}{id:016x}")))?;
                e.insert(Segment {
                    file,
                    len: 0,
                    addrs: Vec::new(),
                })
            }
        };
        let mut record = Vec::with_capacity(RECORD_LEN);
        record.extend_from_slice(&now.to_be_bytes());
        record.extend_from_slice(&addr.0);
        record.extend_from_slice(packet.as_bytes());
        // At the offset the index will record, not wherever the file ends: a write cut short
        // (a full disk) must not shift every record after it.
        let offset = segment.len;
        if let Err(err) = segment.file.write_all_at(&record, offset) {
            segment.file.set_len(offset).ok();
            return Err(err);
        }
        segment.len = segment.len.saturating_add(record_len());
        segment.addrs.push(addr);
        self.index.insert(addr, (id, offset, now));
        self.trim(now)?;
        Ok(true)
    }

    /// The packet at `addr`, if it's there and hasn't expired.
    ///
    /// # Errors
    /// Fails if the disk read fails.
    pub fn get(&self, addr: &BoxAddr, now: u64) -> io::Result<Option<Packet>> {
        let Some((id, offset)) = self.live(addr, now) else {
            return Ok(None);
        };
        let segment = self
            .segments
            .get(&id)
            .ok_or_else(|| io::Error::other("index points at a missing segment"))?;
        let mut record = [0u8; RECORD_LEN];
        segment.file.read_exact_at(&mut record, offset)?;
        let packet = record
            .get(40..)
            .ok_or_else(|| io::Error::other("short record"))?;
        Packet::from_slice(packet).map(Some)
    }

    /// Bytes of records on disk.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.segments
            .values()
            .map(|s| s.len)
            .fold(0, u64::saturating_add)
    }

    fn live(&self, addr: &BoxAddr, now: u64) -> Option<(u64, u64)> {
        self.index
            .get(addr)
            .filter(|(_, _, at)| now.saturating_sub(*at) <= self.limits.retention_secs)
            .map(|(id, offset, _)| (*id, *offset))
    }

    /// Delete segments whose newest possible record has expired, then the oldest ones
    /// while the store is over its cap.
    fn trim(&mut self, now: u64) -> io::Result<()> {
        let horizon = now.saturating_sub(self.limits.retention_secs);
        while let Some((&oldest, _)) = self.segments.first_key_value() {
            let end = oldest.saturating_add(1).saturating_mul(SEGMENT_SECS);
            let expired = end <= horizon;
            if !expired && self.bytes() <= self.limits.max_bytes {
                break;
            }
            self.drop_segment(oldest)?;
        }
        Ok(())
    }

    fn drop_segment(&mut self, id: u64) -> io::Result<()> {
        if let Some(segment) = self.segments.remove(&id) {
            for addr in segment.addrs {
                if self.index.get(&addr).is_some_and(|(seg, _, _)| *seg == id) {
                    self.index.remove(&addr);
                }
            }
        }
        match fs::remove_file(self.dir.join(format!("{PREFIX}{id:016x}"))) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
            Ok(()) | Err(_) => Ok(()),
        }
    }
}

#[expect(
    clippy::as_conversions,
    reason = "RECORD_LEN is 1576; widening usize to u64"
)]
const fn record_len() -> u64 {
    RECORD_LEN as u64
}

fn header(record: &[u8; RECORD_LEN]) -> io::Result<(u64, BoxAddr)> {
    let (at, rest) = record
        .split_first_chunk::<8>()
        .ok_or_else(|| io::Error::other("short record"))?;
    let (addr, _) = rest
        .split_first_chunk::<32>()
        .ok_or_else(|| io::Error::other("short record"))?;
    Ok((u64::from_be_bytes(*at), BoxAddr(*addr)))
}

fn segment_id(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?.strip_prefix(PREFIX)?;
    u64::from_str_radix(name, 16).ok()
}

/// A [`DiskStore`] shared between connections, on the wall clock.
#[derive(Debug)]
pub struct SharedStore(pub Mutex<DiskStore>);

fn unix_now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(io::Error::other)
}

fn poisoned<T>(_: PoisonError<T>) -> io::Error {
    io::Error::other("store lock poisoned")
}

impl Boxes for SharedStore {
    fn put(&self, addr: BoxAddr, packet: Packet) -> io::Result<bool> {
        self.0
            .lock()
            .map_err(poisoned)?
            .put(addr, &packet, unix_now()?)
    }

    fn get(&self, addr: &BoxAddr) -> io::Result<Option<Packet>> {
        self.0.lock().map_err(poisoned)?.get(addr, unix_now()?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::path::PathBuf;

    use purple_ipc::PACKET_LEN;

    use super::*;

    const HOUR: u64 = 3600;
    const T0: u64 = 1_800_000_000;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("purple-store-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    fn limits() -> Limits {
        Limits {
            retention_secs: 7 * 24 * HOUR,
            max_bytes: u64::MAX,
        }
    }

    #[test]
    fn boxes_are_write_once() {
        let d = dir("once");
        let mut s = DiskStore::open(&d, limits(), T0).unwrap();
        assert!(s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap());
        assert!(!s.put(BoxAddr([1; 32]), &packet(2), T0).unwrap());
        assert_eq!(s.get(&BoxAddr([1; 32]), T0).unwrap(), Some(packet(1)));
        assert_eq!(s.get(&BoxAddr([2; 32]), T0).unwrap(), None);
    }

    #[test]
    fn boxes_survive_reopen() {
        let d = dir("reopen");
        let mut s = DiskStore::open(&d, limits(), T0).unwrap();
        s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap();
        s.put(BoxAddr([2; 32]), &packet(2), T0 + 2 * HOUR).unwrap();
        drop(s);
        let reopened = DiskStore::open(&d, limits(), T0 + 3 * HOUR).unwrap();
        assert_eq!(
            reopened.get(&BoxAddr([1; 32]), T0 + 3 * HOUR).unwrap(),
            Some(packet(1))
        );
        assert_eq!(
            reopened.get(&BoxAddr([2; 32]), T0 + 3 * HOUR).unwrap(),
            Some(packet(2))
        );
    }

    #[test]
    fn expired_boxes_read_empty_and_their_segments_go() {
        let d = dir("expiry");
        let short = Limits {
            retention_secs: HOUR,
            max_bytes: u64::MAX,
        };
        let mut s = DiskStore::open(&d, short, T0).unwrap();
        s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap();
        assert_eq!(s.get(&BoxAddr([1; 32]), T0 + 2 * HOUR).unwrap(), None);
        // The next write sweeps the old segment off the disk.
        s.put(BoxAddr([2; 32]), &packet(2), T0 + 3 * HOUR).unwrap();
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        // An expired box can be written again.
        assert!(s.put(BoxAddr([1; 32]), &packet(3), T0 + 3 * HOUR).unwrap());
    }

    #[test]
    fn the_cap_evicts_the_oldest_segment() {
        let d = dir("cap");
        let record = u64::try_from(RECORD_LEN).unwrap();
        let tight = Limits {
            retention_secs: 7 * 24 * HOUR,
            max_bytes: 2 * record,
        };
        let mut s = DiskStore::open(&d, tight, T0).unwrap();
        s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap();
        s.put(BoxAddr([2; 32]), &packet(2), T0 + HOUR).unwrap();
        s.put(BoxAddr([3; 32]), &packet(3), T0 + 2 * HOUR).unwrap();
        assert_eq!(s.get(&BoxAddr([1; 32]), T0 + 2 * HOUR).unwrap(), None);
        assert!(s.get(&BoxAddr([3; 32]), T0 + 2 * HOUR).unwrap().is_some());
        assert!(s.bytes() <= 2 * record);
    }

    #[test]
    fn a_partial_write_while_open_does_not_shift_later_records() {
        let d = dir("partial");
        let mut s = DiskStore::open(&d, limits(), T0).unwrap();
        s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap();
        // What a write cut short by a full disk leaves behind.
        let segment = fs::read_dir(&d).unwrap().next().unwrap().unwrap().path();
        OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(&[9; 100])
            .unwrap();
        s.put(BoxAddr([2; 32]), &packet(2), T0).unwrap();
        assert_eq!(s.get(&BoxAddr([2; 32]), T0).unwrap(), Some(packet(2)));
        drop(s);
        let reopened = DiskStore::open(&d, limits(), T0).unwrap();
        assert_eq!(
            reopened.get(&BoxAddr([1; 32]), T0).unwrap(),
            Some(packet(1))
        );
        assert_eq!(
            reopened.get(&BoxAddr([2; 32]), T0).unwrap(),
            Some(packet(2))
        );
    }

    #[test]
    fn torn_tail_record_is_ignored_on_reopen() {
        let d = dir("torn");
        let mut s = DiskStore::open(&d, limits(), T0).unwrap();
        s.put(BoxAddr([1; 32]), &packet(1), T0).unwrap();
        drop(s);
        let segment = fs::read_dir(&d).unwrap().next().unwrap().unwrap().path();
        OpenOptions::new()
            .append(true)
            .open(&segment)
            .unwrap()
            .write_all(&[9; 100])
            .unwrap();
        let mut cut = DiskStore::open(&d, limits(), T0).unwrap();
        assert_eq!(cut.get(&BoxAddr([1; 32]), T0).unwrap(), Some(packet(1)));
        assert!(cut.put(BoxAddr([2; 32]), &packet(2), T0).unwrap());
        drop(cut);
        let again = DiskStore::open(&d, limits(), T0).unwrap();
        assert_eq!(again.get(&BoxAddr([2; 32]), T0).unwrap(), Some(packet(2)));
    }
}
