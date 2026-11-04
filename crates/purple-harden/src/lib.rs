//! Process hardening applied at the start of every purple process.
//!
//! Landlock, seccomp and `memfd_secret` key storage land here as later steps.

use std::io;

/// Apply the hardening every purple process needs. Call it first thing in `main`.
///
/// # Errors
/// Fails if any hardening step can't be applied. Callers must not continue in that case.
pub fn harden() -> io::Result<()> {
    set_non_dumpable()
}

/// Disable core dumps and block `ptrace` from other processes running as the same user.
///
/// # Errors
/// Fails if the kernel rejects the `prctl` call.
#[expect(unsafe_code, reason = "prctl has no safe wrapper in std")]
pub fn set_non_dumpable() -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes only integer arguments and touches no memory.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether the current process can be dumped or traced by its own user.
///
/// # Errors
/// Fails if the kernel rejects the `prctl` call.
#[expect(unsafe_code, reason = "prctl has no safe wrapper in std")]
pub fn is_dumpable() -> io::Result<bool> {
    // SAFETY: PR_GET_DUMPABLE takes only integer arguments and touches no memory.
    let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_makes_process_non_dumpable() {
        harden().unwrap();
        assert!(!is_dumpable().unwrap());
    }
}
