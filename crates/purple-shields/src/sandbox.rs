//! In-process sandboxing with Landlock and a seccomp deny-list.
//!
//! Landlock confines the filesystem, TCP and signals; seccomp kills the process on syscalls
//! an exploit would want. It works with or without bubblewrap around the process, and is
//! the only sandbox when bwrap is unavailable.
//!
//! Call [`restrict`] at the top of `main`, before starting any thread: both Landlock and
//! seccomp apply to the calling thread and every thread it creates afterwards.
//!
//! The seccomp filter is a deny-list rather than an allowlist on purpose: an allowlist
//! across glibc, Rust std and every dependency breaks whenever one of them changes which
//! syscalls it uses. Denied syscalls kill the whole process.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope, path_beneath_rules,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// The newest Landlock ABI purple asks for. Older kernels get what they support.
const LANDLOCK_ABI: ABI = ABI::V6;

/// Whether the process may open network connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// May create sockets and use TCP (`purple-subspace`, `purple-holodeck`).
    Allowed,
    /// May create Unix sockets only, to reach a local daemon such as kpclientd. No TCP,
    /// no UDP, no raw or netlink sockets.
    Local,
    /// May not create sockets at all; existing inherited sockets keep working.
    Denied,
}

/// What a process may still do after [`restrict`].
#[derive(Clone, Copy, Debug)]
pub struct Policy<'a> {
    /// Directories it may read and write beneath. Everything else on disk is off limits.
    pub writable: &'a [&'a Path],
    /// Whether it may use the network.
    pub network: Network,
}

/// How much of the policy the kernel enforced.
#[derive(Debug)]
pub struct Report {
    /// Landlock enforcement. Seccomp is always enforced, or [`restrict`] fails.
    pub landlock: RulesetStatus,
}

/// Apply `policy` to this process. See the module docs.
///
/// # Errors
/// Fails if the seccomp filter can't be installed, or Landlock rejects the policy. Callers
/// must not continue in that case.
pub fn restrict(policy: &Policy<'_>) -> io::Result<Report> {
    let landlock = restrict_landlock(policy)?;
    restrict_syscalls(policy.network)?;
    Ok(Report { landlock })
}

fn restrict_landlock(policy: &Policy<'_>) -> io::Result<RulesetStatus> {
    let all_fs = AccessFs::from_all(LANDLOCK_ABI);
    let mut ruleset = Ruleset::default()
        .handle_access(all_fs)
        .map_err(io::Error::other)?
        .scope(Scope::from_all(LANDLOCK_ABI))
        .map_err(io::Error::other)?;
    if policy.network != Network::Allowed {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(LANDLOCK_ABI))
            .map_err(io::Error::other)?;
    }
    let status = ruleset
        .create()
        .map_err(io::Error::other)?
        .add_rules(path_beneath_rules(policy.writable, all_fs))
        .map_err(io::Error::other)?
        .restrict_self()
        .map_err(io::Error::other)?;
    Ok(status.ruleset)
}

fn restrict_syscalls(network: Network) -> io::Result<()> {
    for program in filters(network, Exec::Deny)? {
        seccompiler::apply_filter(&program).map_err(io::Error::other)?;
    }
    Ok(())
}

/// Whether the filter denies `execve`/`execveat`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Exec {
    Deny,
    Allow,
}

/// The seccomp filters [`restrict`] installs, as raw BPF programs.
///
/// Each is a `struct sock_filter` array in native byte order. They're for processes purple
/// can't modify, such as `kpclientd`: bubblewrap installs them with `--add-seccomp-fd`
/// and then has to exec the program, so these leave `execve` and `execveat` allowed.
/// Everything else on the deny-list still applies.
///
/// # Errors
/// Fails only if a filter can't be compiled.
pub fn seccomp_programs(network: Network) -> io::Result<Vec<Vec<u8>>> {
    Ok(filters(network, Exec::Allow)?
        .iter()
        .map(|program| {
            program
                .iter()
                .flat_map(|insn| {
                    let mut bytes = Vec::with_capacity(8);
                    bytes.extend_from_slice(&insn.code.to_ne_bytes());
                    bytes.push(insn.jt);
                    bytes.push(insn.jf);
                    bytes.extend_from_slice(&insn.k.to_ne_bytes());
                    bytes
                })
                .collect()
        })
        .collect())
}

fn filters(network: Network, exec: Exec) -> io::Result<[BpfProgram; 2]> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(io::Error::other)?;
    let deny = SeccompFilter::new(
        denied_syscalls(network, exec)?,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        arch,
    )
    .map_err(io::Error::other)?;
    // clone3 passes its flags behind a pointer, which seccomp can't inspect. Failing it with
    // ENOSYS makes glibc fall back to clone, whose flags the deny filter does check.
    let clone3 = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(u32::try_from(libc::ENOSYS).map_err(io::Error::other)?),
        arch,
    )
    .map_err(io::Error::other)?;
    Ok([
        BpfProgram::try_from(deny).map_err(io::Error::other)?,
        BpfProgram::try_from(clone3).map_err(io::Error::other)?,
    ])
}

/// Syscalls no purple process needs once running.
const ALWAYS_DENIED: &[libc::c_long] = &[
    // Reading or controlling other processes. (`execve` is added separately: see `Exec`.)
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // Kernel attack surface.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_personality,
    // Namespaces and mounts.
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_open_tree,
    libc::SYS_move_mount,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_name_to_handle_at,
    libc::SYS_open_by_handle_at,
    // System administration.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_quotactl,
    libc::SYS_syslog,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_adjtimex,
    libc::SYS_clock_adjtime,
    libc::SYS_vhangup,
];

/// Additionally denied when the process may not use the network. `socketpair` stays
/// allowed: it only makes a connected pair of local sockets (crossterm's signal handling
/// needs one), and can't reach anything outside the process.
const NETWORK_DENIED: &[libc::c_long] = &[libc::SYS_socket];

/// `ioctl` requests that inject input into or control a terminal.
const DENIED_IOCTLS: &[libc::c_ulong] = &[libc::TIOCSTI, libc::TIOCLINUX];

/// `clone` flags that create namespaces.
const NAMESPACE_FLAGS: &[libc::c_int] = &[
    libc::CLONE_NEWNS,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWNET,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWCGROUP,
];

fn denied_syscalls(network: Network, exec: Exec) -> io::Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let network_denied = if network == Network::Denied {
        NETWORK_DENIED
    } else {
        &[]
    };
    let exec_denied: &[libc::c_long] = if exec == Exec::Deny {
        &[libc::SYS_execve, libc::SYS_execveat]
    } else {
        &[]
    };
    for &nr in ALWAYS_DENIED
        .iter()
        .chain(network_denied)
        .chain(exec_denied)
    {
        // An empty rule list matches every call to the syscall.
        rules.insert(nr, Vec::new());
    }

    if network == Network::Local {
        // The domain is an int; compare only its 32 bits.
        let other_domains = rule(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, libc::AF_UNIX)?;
        rules.insert(libc::SYS_socket, vec![other_domains]);
    }

    // The kernel reads an ioctl request as a 32-bit value, so compare only those bits.
    let ioctl_rules = DENIED_IOCTLS
        .iter()
        .map(|&request| rule(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, request))
        .collect::<io::Result<_>>()?;
    rules.insert(libc::SYS_ioctl, ioctl_rules);

    let clone_rules = NAMESPACE_FLAGS
        .iter()
        .map(|&flag| {
            let flag = u64::try_from(flag).map_err(io::Error::other)?;
            rule(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag),
                flag,
            )
        })
        .collect::<io::Result<_>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    Ok(rules)
}

fn rule(
    arg: u8,
    len: SeccompCmpArgLen,
    op: SeccompCmpOp,
    value: impl TryInto<u64>,
) -> io::Result<SeccompRule> {
    let value = value
        .try_into()
        .map_err(|_| io::Error::other("seccomp value out of range"))?;
    let condition = SeccompCondition::new(arg, len, op, value).map_err(io::Error::other)?;
    SeccompRule::new(vec![condition]).map_err(io::Error::other)
}

/// Each test that restricts itself runs in a fresh copy of the test binary, so the
/// restrictions (and any kill) don't hit the test harness.
#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Command, ExitStatus};

    use super::*;

    const CHILD_ENV: &str = "PURPLE_SANDBOX_TEST_CHILD";

    /// True inside the child copy running `test`.
    fn is_child(test: &str) -> bool {
        std::env::var(CHILD_ENV).as_deref() == Ok(test)
    }

    fn run_child(test: &str) -> ExitStatus {
        Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, test)
            .status()
            .unwrap()
    }

    fn assert_killed_by_seccomp(status: ExitStatus) {
        assert_eq!(status.signal(), Some(libc::SIGSYS), "{status:?}");
    }

    fn locked_down() -> Report {
        restrict(&Policy {
            writable: &[],
            network: Network::Denied,
        })
        .unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("purple-sandbox-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LANDLOCK_TEST: &str = "sandbox::tests::landlock_confines_files_to_writable_dirs";
    #[test]
    fn landlock_confines_files_to_writable_dirs() {
        if is_child(LANDLOCK_TEST) {
            let allowed = scratch("allowed");
            let other = scratch("other");
            std::fs::write(other.join("secret"), b"x").unwrap();
            let report = restrict(&Policy {
                writable: &[&allowed],
                network: Network::Denied,
            })
            .unwrap();
            assert_eq!(report.landlock, RulesetStatus::FullyEnforced);

            std::fs::write(allowed.join("ok"), b"fine").unwrap();
            assert_eq!(std::fs::read(allowed.join("ok")).unwrap(), b"fine");
            assert!(std::fs::read(other.join("secret")).is_err());
            assert!(std::fs::write(other.join("new"), b"x").is_err());
            assert!(std::fs::read("/etc/hostname").is_err());
            assert!(std::fs::read_dir("/").is_err());
            return;
        }
        assert!(run_child(LANDLOCK_TEST).success());
    }

    const THREADS_TEST: &str = "sandbox::tests::threads_still_start_after_restricting";
    #[test]
    fn threads_still_start_after_restricting() {
        if is_child(THREADS_TEST) {
            locked_down();
            assert_eq!(std::thread::spawn(|| 2 + 2).join().unwrap(), 4);
            return;
        }
        assert!(run_child(THREADS_TEST).success());
    }

    const PTRACE_TEST: &str = "sandbox::tests::ptrace_kills_the_process";
    #[test]
    #[expect(unsafe_code, reason = "calling a denied syscall directly")]
    fn ptrace_kills_the_process() {
        if is_child(PTRACE_TEST) {
            locked_down();
            // SAFETY: PTRACE_TRACEME takes no pointers; the filter should kill us here.
            unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) };
            return;
        }
        assert_killed_by_seccomp(run_child(PTRACE_TEST));
    }

    const EXEC_TEST: &str = "sandbox::tests::execve_kills_the_process";
    #[test]
    #[expect(unsafe_code, reason = "calling a denied syscall directly")]
    fn execve_kills_the_process() {
        if is_child(EXEC_TEST) {
            locked_down();
            let path = c"/usr/bin/true";
            let argv = [path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            // SAFETY: valid NUL-terminated path and NULL-terminated argv/envp arrays.
            unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            return;
        }
        assert_killed_by_seccomp(run_child(EXEC_TEST));
    }

    const UNSHARE_TEST: &str = "sandbox::tests::new_namespaces_kill_the_process";
    #[test]
    #[expect(unsafe_code, reason = "calling a denied syscall directly")]
    fn new_namespaces_kill_the_process() {
        if is_child(UNSHARE_TEST) {
            locked_down();
            // SAFETY: unshare takes only flags; the filter should kill us here.
            unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            return;
        }
        assert_killed_by_seccomp(run_child(UNSHARE_TEST));
    }

    const TIOCSTI_TEST: &str = "sandbox::tests::terminal_injection_kills_the_process";
    #[test]
    #[expect(unsafe_code, reason = "calling a denied syscall directly")]
    fn terminal_injection_kills_the_process() {
        if is_child(TIOCSTI_TEST) {
            locked_down();
            let byte: libc::c_char = 0;
            // SAFETY: TIOCSTI reads one byte from a valid pointer; the filter should kill us
            // before the kernel looks at the fd.
            unsafe { libc::ioctl(0, libc::TIOCSTI, &raw const byte) };
            return;
        }
        assert_killed_by_seccomp(run_child(TIOCSTI_TEST));
    }

    const NO_NET_TEST: &str = "sandbox::tests::sockets_kill_a_process_without_network";
    #[test]
    fn sockets_kill_a_process_without_network() {
        if is_child(NO_NET_TEST) {
            locked_down();
            drop(std::net::TcpListener::bind("127.0.0.1:0"));
            return;
        }
        assert_killed_by_seccomp(run_child(NO_NET_TEST));
    }

    const SOCKETPAIR_TEST: &str = "sandbox::tests::local_socket_pairs_still_work_without_network";
    #[test]
    fn local_socket_pairs_still_work_without_network() {
        if is_child(SOCKETPAIR_TEST) {
            locked_down();
            let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
            io::Write::write_all(&mut a, b"x").unwrap();
            let mut byte = [0u8; 1];
            io::Read::read_exact(&mut b, &mut byte).unwrap();
            assert_eq!(&byte, b"x");
            return;
        }
        assert!(run_child(SOCKETPAIR_TEST).success());
    }

    fn local_only() {
        restrict(&Policy {
            writable: &[],
            network: Network::Local,
        })
        .unwrap();
    }

    const LOCAL_UNIX_TEST: &str = "sandbox::tests::local_network_keeps_unix_sockets";
    #[test]
    fn local_network_keeps_unix_sockets() {
        if is_child(LOCAL_UNIX_TEST) {
            // Bind before restricting: Landlock forbids making the socket file afterwards.
            let dir = socket_test_dir(std::os::unix::process::parent_id());
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("s");
            let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
            local_only();
            let mut client = std::os::unix::net::UnixStream::connect(&path).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            io::Write::write_all(&mut client, b"x").unwrap();
            let mut byte = [0u8; 1];
            io::Read::read_exact(&mut server, &mut byte).unwrap();
            assert_eq!(&byte, b"x");
            return;
        }
        let ok = run_child(LOCAL_UNIX_TEST).success();
        std::fs::remove_dir_all(socket_test_dir(std::process::id())).ok();
        assert!(ok);
    }

    /// Where the Unix socket test's socket goes, named after the parent test process.
    fn socket_test_dir(pid: u32) -> PathBuf {
        std::env::temp_dir().join(format!("purple-sock-{pid}"))
    }

    const LOCAL_TCP_TEST: &str = "sandbox::tests::local_network_kills_tcp";
    #[test]
    fn local_network_kills_tcp() {
        if is_child(LOCAL_TCP_TEST) {
            local_only();
            drop(std::net::TcpStream::connect("127.0.0.1:9"));
            return;
        }
        assert_killed_by_seccomp(run_child(LOCAL_TCP_TEST));
    }

    #[test]
    fn exported_programs_are_whole_bpf_instructions() {
        for network in [Network::Allowed, Network::Local, Network::Denied] {
            let programs = seccomp_programs(network).unwrap();
            assert_eq!(programs.len(), 2);
            for program in programs {
                assert!(!program.is_empty());
                assert_eq!(program.len() % 8, 0);
            }
        }
    }

    const NET_TEST: &str = "sandbox::tests::network_process_keeps_tcp";
    #[test]
    fn network_process_keeps_tcp() {
        if is_child(NET_TEST) {
            restrict(&Policy {
                writable: &[],
                network: Network::Allowed,
            })
            .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            assert!(std::fs::read("/etc/hostname").is_err());
            return;
        }
        assert!(run_child(NET_TEST).success());
    }
}
