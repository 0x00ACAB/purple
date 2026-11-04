//! A page of memory for long-lived secrets such as the storage master key.
//!
//! Where the kernel supports it, the page comes from `memfd_secret`: it is removed from the
//! kernel's direct map, so even kernel memory-read bugs (and other processes, including root
//! reading `/proc/<pid>/mem`) can't see it. Otherwise it's an anonymous mapping that is
//! `mlock`ed (never swapped) and excluded from core dumps. Either way it's zeroed before
//! it's unmapped.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;

use zeroize::Zeroize;

/// How a [`SecretPage`] is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// `memfd_secret`: not in the kernel's direct map.
    MemfdSecret,
    /// Fallback: `mlock`ed and excluded from core dumps.
    Locked,
}

/// Up to one page of secret bytes. See the module docs.
pub struct SecretPage {
    ptr: NonNull<u8>,
    map_len: usize,
    len: usize,
    protection: Protection,
}

impl std::fmt::Debug for SecretPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPage")
            .field("len", &self.len)
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

impl SecretPage {
    /// Allocate `len` zeroed secret bytes.
    ///
    /// # Errors
    /// Fails if `len` is larger than a page, or the kernel refuses every way of mapping it.
    pub fn new(len: usize) -> io::Result<Self> {
        let map_len = page_size()?;
        if len > map_len {
            return Err(io::Error::other("secret larger than a page"));
        }
        let (ptr, protection) = match map_memfd_secret(map_len)? {
            Some(ptr) => (ptr, Protection::MemfdSecret),
            None => (map_locked(map_len)?, Protection::Locked),
        };
        Ok(Self {
            ptr,
            map_len,
            len,
            protection,
        })
    }

    /// How this page is protected.
    #[must_use]
    pub const fn protection(&self) -> Protection {
        self.protection
    }

    /// The secret bytes.
    #[must_use]
    #[expect(unsafe_code, reason = "viewing the mapped page as a slice")]
    pub const fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to a live mapping of `map_len >= len` bytes owned by `self`,
        // and the borrow of `self` keeps it alive and unaliased by `&mut` access.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// The secret bytes, writable.
    #[must_use]
    #[expect(unsafe_code, reason = "viewing the mapped page as a slice")]
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as in `as_slice`, and `&mut self` makes this the only access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for SecretPage {
    #[expect(unsafe_code, reason = "unmapping the page")]
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        // SAFETY: `ptr`/`map_len` describe a mapping created in `new` and not yet unmapped.
        // A failure here leaves zeroed memory mapped, which is harmless.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.map_len) };
    }
}

/// Map one page from `memfd_secret`. `Ok(None)` when the kernel doesn't offer it.
#[expect(
    unsafe_code,
    reason = "memfd_secret, ftruncate and mmap have no safe wrappers"
)]
fn map_memfd_secret(map_len: usize) -> io::Result<Option<NonNull<u8>>> {
    // SAFETY: memfd_secret takes a flags integer and returns a new fd or -1.
    let raw = unsafe { libc::syscall(libc::SYS_memfd_secret, 0) };
    if raw < 0 {
        return Ok(None);
    }
    let raw = RawFd::try_from(raw).map_err(io::Error::other)?;
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let size = libc::off_t::try_from(map_len).map_err(io::Error::other)?;
    // SAFETY: ftruncate on an fd we own, with a valid size.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh shared mapping of the whole fd; the kernel picks the address.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    // The mapping keeps the memory alive after the fd closes.
    drop(fd);
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(NonNull::new(ptr.cast()))
}

/// Map one anonymous page, lock it in RAM and exclude it from core dumps.
#[expect(unsafe_code, reason = "mmap, mlock and madvise have no safe wrappers")]
fn map_locked(map_len: usize) -> io::Result<NonNull<u8>> {
    // SAFETY: a fresh private anonymous mapping; the kernel picks the address.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let unmap = |err: io::Error| {
        // SAFETY: undoing the mapping created just above.
        unsafe { libc::munmap(ptr, map_len) };
        err
    };
    // SAFETY: locking the mapping created above, which is `map_len` bytes long.
    if unsafe { libc::mlock(ptr, map_len) } != 0 {
        return Err(unmap(io::Error::last_os_error()));
    }
    // SAFETY: advising on the mapping created above.
    if unsafe { libc::madvise(ptr, map_len, libc::MADV_DONTDUMP) } != 0 {
        return Err(unmap(io::Error::last_os_error()));
    }
    NonNull::new(ptr.cast()).ok_or_else(|| io::Error::other("mmap returned null"))
}

#[expect(unsafe_code, reason = "sysconf has no safe wrapper")]
fn page_size() -> io::Result<usize> {
    // SAFETY: sysconf only reads a configuration value.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).map_err(|_| io::Error::other("sysconf(_SC_PAGESIZE) failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_returns_bytes() {
        let mut page = SecretPage::new(32).unwrap();
        assert_eq!(page.as_slice(), [0; 32]);
        page.as_mut_slice().copy_from_slice(&[7; 32]);
        assert_eq!(page.as_slice(), [7; 32]);
        eprintln!("secret page protection: {:?}", page.protection());
    }

    #[test]
    fn locked_fallback_works() {
        let ptr = map_locked(page_size().unwrap()).unwrap();
        let page = SecretPage {
            ptr,
            map_len: page_size().unwrap(),
            len: 16,
            protection: Protection::Locked,
        };
        assert_eq!(page.as_slice(), [0; 16]);
    }

    #[test]
    fn rejects_more_than_a_page() {
        assert!(SecretPage::new(page_size().unwrap() + 1).is_err());
    }
}
