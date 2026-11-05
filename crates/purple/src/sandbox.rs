//! bubblewrap profiles for each purple process, and the fallback when bwrap can't run.

use std::ffi::OsString;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where the binaries directory is mounted inside every sandbox.
const APP_DIR: &str = "/app";
/// Where `purple-net` keeps its state inside its sandbox.
const NET_STATE_DIR: &str = "/state";
/// Where `purple-core` keeps its database inside its sandbox.
pub(crate) const CORE_DATA_DIR: &str = "/data";
/// Where `kpclientd`'s socket directory is mounted, in its sandbox and in `purple-net`'s.
pub(crate) const KP_SOCKET_DIR: &str = "/run/kp";
/// The socket path `kpclientd`'s config must listen on.
pub(crate) const KP_SOCKET: &str = "/run/kp/kpclientd.sock";
/// Where the `kpclientd` binary and its config are mounted in its sandbox.
const KP_BINARY: &str = "/opt/kpclientd";
pub(crate) const KP_CONFIG: &str = "/etc/purple/kpclientd.toml";
/// The TPM resource manager, the one device `purple-core` gets (same as
/// `purple_core::tpm::TPM_DEVICE`).
const TPM_DEVICE: &str = "/dev/tpmrm0";
/// Where tor's socket directory is mounted, in its sandbox and in `purple-net`'s.
pub(crate) const TOR_SOCKET_DIR: &str = "/run/tor";
/// tor's SOCKS socket.
pub(crate) const TOR_SOCKS: &str = "/run/tor/socks.sock";
/// Where tor's control socket directory is mounted, in tor's sandbox and purple-torctl's.
/// Never in purple-net's.
pub(crate) const TORCTL_SOCKET_DIR: &str = "/run/torctl";
/// tor's control socket.
pub(crate) const TOR_CONTROL: &str = "/run/torctl/control.sock";
/// The cookie file for tor's control socket.
pub(crate) const TOR_COOKIE: &str = "/run/torctl/control.cookie";
/// Where tor keeps its state inside its sandbox.
pub(crate) const TOR_DATA_DIR: &str = "/var/lib/tor";
/// Where tor's torrc is mounted.
pub(crate) const TOR_RC: &str = "/etc/purple/torrc";
/// The tor binary, from the system package.
const TOR_BINARY: &str = "/usr/bin/tor";
/// Where purple-relay's socket directory is mounted, in its sandbox and in `purple-net`'s.
pub(crate) const RELAY_SOCKET_DIR: &str = "/run/relay";
/// purple-relay's socket.
pub(crate) const RELAY_SOCKET: &str = "/run/relay/relay.sock";
/// Fds bwrap reads the seccomp filters for daemons purple can't modify (kpclientd, tor)
/// from.
pub(crate) const DAEMON_SECCOMP_FDS: [RawFd; 2] = [10, 11];

const MAX_PASSED_FDS: usize = 4;

/// What one purple process is allowed to reach.
#[derive(Debug)]
pub(crate) enum Profile {
    /// Its own state directory, and the socket directories (read-only, host path and where
    /// it's mounted) of the daemons that do its networking. With none, it gets network
    /// access itself.
    Net {
        state_dir: PathBuf,
        sockets: Vec<(PathBuf, &'static str)>,
    },
    /// Its own data directory. No network, no display.
    Core { data_dir: PathBuf },
    /// The terminal it inherits only. No network, nothing writable. `WAYLAND_DISPLAY` is
    /// passed through so `purple-ui` can refuse to run outside a Wayland session.
    Ui { wayland_display: OsString },
    /// Katzenpost's client daemon: network access, its config read-only, and the directory
    /// it creates its socket in. purple can't modify it, so bwrap installs purple's seccomp
    /// filters on it (from [`DAEMON_SECCOMP_FDS`]).
    KpClientd {
        binary: PathBuf,
        config: PathBuf,
        socket_dir: PathBuf,
    },
    /// C tor: network access, its data directory (kept across runs so its guards stay the
    /// same), the directory it makes its SOCKS socket in, a separate one for its control
    /// socket and cookie, its torrc read-only, and purple's seccomp filters from
    /// [`DAEMON_SECCOMP_FDS`]. Pluggable transports run as its children from /usr/bin and
    /// need DNS and CA certificates.
    Tor {
        data_dir: PathBuf,
        socket_dir: PathBuf,
        control_dir: PathBuf,
        torrc: PathBuf,
    },
    /// purple-relay: network access and the directory it makes its socket in.
    Relay { socket_dir: PathBuf },
    /// purple-torctl: tor's control directory read-only. No network, nothing writable.
    TorCtl { control_dir: PathBuf },
}

impl Profile {
    pub(crate) const fn binary(&self) -> &'static str {
        match self {
            Self::Net { .. } => "purple-net",
            Self::Core { .. } => "purple-core",
            Self::Ui { .. } => "purple-ui",
            Self::KpClientd { .. } => "kpclientd",
            Self::Tor { .. } => "tor",
            Self::Relay { .. } => "purple-relay",
            Self::TorCtl { .. } => "purple-torctl",
        }
    }

    /// The program to run inside the sandbox.
    fn exec_path(&self) -> PathBuf {
        match self {
            Self::KpClientd { .. } => PathBuf::from(KP_BINARY),
            Self::Tor { .. } => PathBuf::from(TOR_BINARY),
            Self::Net { .. }
            | Self::Core { .. }
            | Self::Ui { .. }
            | Self::Relay { .. }
            | Self::TorCtl { .. } => Path::new(APP_DIR).join(self.binary()),
        }
    }
}

/// Whether bwrap can create a sandbox here. It can't when unprivileged user namespaces are
/// disabled, as Ubuntu's default security policy does.
pub(crate) fn bwrap_works() -> bool {
    Command::new("bwrap")
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "/usr/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Arguments that run `profile`'s binary from `bin_dir` under bwrap.
pub(crate) fn bwrap_args(profile: &Profile, bin_dir: &Path, args: &[&str]) -> Vec<OsString> {
    let mut out: Vec<OsString> = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib",
        "/lib64",
        "--symlink",
        "usr/bin",
        "/bin",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    out.extend(["--ro-bind".into(), bin_dir.into(), APP_DIR.into()]);

    match profile {
        Profile::Net { state_dir, sockets } => {
            if sockets.is_empty() {
                share_net(&mut out);
            }
            // Otherwise the daemons do the networking; purple-net gets only their sockets
            // and no network namespace of its own.
            for (dir, inside) in sockets {
                out.extend(["--ro-bind".into(), dir.into(), (*inside).into()]);
            }
            out.extend(["--bind".into(), state_dir.into(), NET_STATE_DIR.into()]);
        }
        Profile::Core { data_dir } => {
            out.extend(["--bind".into(), data_dir.into(), CORE_DATA_DIR.into()]);
            // The TPM, for vaults sealed to it. Skipped where there is none.
            out.extend([
                "--dev-bind-try".into(),
                TPM_DEVICE.into(),
                TPM_DEVICE.into(),
            ]);
        }
        Profile::Ui { wayland_display } => {
            out.extend([
                "--setenv".into(),
                "WAYLAND_DISPLAY".into(),
                wayland_display.clone(),
            ]);
        }
        Profile::KpClientd {
            binary,
            config,
            socket_dir,
        } => {
            out.push("--share-net".into());
            out.extend(["--ro-bind".into(), binary.into(), KP_BINARY.into()]);
            out.extend(["--ro-bind".into(), config.into(), KP_CONFIG.into()]);
            out.extend(["--bind".into(), socket_dir.into(), KP_SOCKET_DIR.into()]);
            for fd in DAEMON_SECCOMP_FDS {
                out.extend(["--add-seccomp-fd".into(), fd.to_string().into()]);
            }
        }
        Profile::Tor {
            data_dir,
            socket_dir,
            control_dir,
            torrc,
        } => {
            share_net(&mut out);
            out.extend(["--bind".into(), data_dir.into(), TOR_DATA_DIR.into()]);
            out.extend(["--bind".into(), socket_dir.into(), TOR_SOCKET_DIR.into()]);
            out.extend([
                "--bind".into(),
                control_dir.into(),
                TORCTL_SOCKET_DIR.into(),
            ]);
            out.extend(["--ro-bind".into(), torrc.into(), TOR_RC.into()]);
            for fd in DAEMON_SECCOMP_FDS {
                out.extend(["--add-seccomp-fd".into(), fd.to_string().into()]);
            }
        }
        Profile::Relay { socket_dir } => {
            out.push("--share-net".into());
            out.extend(["--bind".into(), socket_dir.into(), RELAY_SOCKET_DIR.into()]);
        }
        Profile::TorCtl { control_dir } => {
            out.extend([
                "--ro-bind".into(),
                control_dir.into(),
                TORCTL_SOCKET_DIR.into(),
            ]);
        }
    }

    out.extend(["--chdir".into(), "/".into(), profile.exec_path().into()]);
    out.extend(args.iter().map(OsString::from));
    out
}

/// The host's network, with DNS and CA certificates.
fn share_net(out: &mut Vec<OsString>) {
    out.push("--share-net".into());
    for path in ["/etc/resolv.conf", "/etc/ssl", "/etc/ca-certificates"] {
        out.extend(["--ro-bind-try", path, path].map(OsString::from));
    }
}

/// Build the command for `profile`, sandboxed with bwrap or, when `sandboxed` is false,
/// started directly with a cleared environment.
pub(crate) fn command(
    profile: &Profile,
    bin_dir: &Path,
    sandboxed: bool,
    args: &[&str],
) -> Command {
    if sandboxed {
        let mut cmd = Command::new("bwrap");
        cmd.args(bwrap_args(profile, bin_dir, args));
        return cmd;
    }
    let mut cmd = Command::new(bin_dir.join(profile.binary()));
    cmd.env_clear().args(args);
    if let Profile::Ui { wayland_display } = profile {
        cmd.env("WAYLAND_DISPLAY", wayland_display);
    }
    cmd
}

/// Make each `(source, target)` fd available to the child at `target`.
///
/// # Errors
/// Fails if more than [`MAX_PASSED_FDS`] fds are passed.
#[expect(unsafe_code, reason = "pre_exec runs between fork and exec")]
pub(crate) fn pass_fds(cmd: &mut Command, fds: &[(RawFd, RawFd)]) -> io::Result<()> {
    if fds.len() > MAX_PASSED_FDS {
        return Err(io::Error::other("too many fds to pass"));
    }
    let mut map = [(-1, -1); MAX_PASSED_FDS];
    for (slot, &pair) in map.iter_mut().zip(fds) {
        *slot = pair;
    }
    let count = fds.len();

    let child_setup = move || -> io::Result<()> {
        // Copy every source above the target range first, so a dup2 onto one target can't
        // clobber a source that happens to sit on another target's number.
        let mut temps = [-1; MAX_PASSED_FDS];
        for (temp, &(source, _)) in temps.iter_mut().zip(&map).take(count) {
            // SAFETY: fcntl is async-signal-safe and only duplicates an fd.
            *temp = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 64) };
            if *temp < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // dup2 clears CLOEXEC on the target, so it survives exec; the temps don't.
        for (&temp, &(_, target)) in temps.iter().zip(&map).take(count) {
            // SAFETY: dup2 is async-signal-safe and only rewires an fd.
            if unsafe { libc::dup2(temp, target) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    };
    // SAFETY: the closure only calls fcntl and dup2, both async-signal-safe, and allocates
    // nothing.
    unsafe { cmd.pre_exec(child_setup) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    fn has(args: &[OsString], needle: &str) -> bool {
        args.iter().any(|arg| arg == needle)
    }

    fn kpclientd() -> Profile {
        Profile::KpClientd {
            binary: "/opt/k/kpclientd".into(),
            config: "/cfg/client.toml".into(),
            socket_dir: "/run/user/1000/purple/kp".into(),
        }
    }

    #[test]
    fn kpclientd_gets_network_its_config_socket_dir_and_purples_seccomp() {
        let args = bwrap_args(&kpclientd(), Path::new("/b"), &["-c", KP_CONFIG]);
        assert!(has(&args, "--share-net"));
        assert!(has(&args, "/opt/k/kpclientd") && has(&args, KP_BINARY));
        assert!(has(&args, "/cfg/client.toml") && has(&args, KP_CONFIG));
        assert!(has(&args, "/run/user/1000/purple/kp") && has(&args, KP_SOCKET_DIR));
        assert_eq!(args.iter().filter(|a| *a == "--add-seccomp-fd").count(), 2);
        assert_eq!(args[args.len() - 3], KP_BINARY);
    }

    #[test]
    fn net_sees_the_kpclientd_socket_dir_only_when_asked_and_read_only() {
        let with = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![("/run/user/1000/purple/kp".into(), KP_SOCKET_DIR)],
            },
            Path::new("/b"),
            &[],
        );
        let at = with
            .iter()
            .position(|a| a == "/run/user/1000/purple/kp")
            .unwrap();
        assert_eq!(with[at - 1], "--ro-bind");
        assert_eq!(with[at + 1], KP_SOCKET_DIR);
        // With kpclientd doing the networking, purple-net gets none.
        assert!(!has(&with, "--share-net"));
        let without = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![],
            },
            Path::new("/b"),
            &[],
        );
        assert!(has(&without, "--share-net"));
        let core = bwrap_args(
            &Profile::Core {
                data_dir: "/d".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(!has(&core, KP_SOCKET_DIR));
    }

    #[test]
    fn only_core_gets_the_tpm() {
        let profiles = [
            Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![],
            },
            Profile::Core {
                data_dir: "/d".into(),
            },
            Profile::Ui {
                wayland_display: "wayland-1".into(),
            },
            kpclientd(),
            tor(),
            Profile::Relay {
                socket_dir: "/r".into(),
            },
            Profile::TorCtl {
                control_dir: "/c".into(),
            },
        ];
        for profile in &profiles {
            let args = bwrap_args(profile, Path::new("/b"), &[]);
            let core = matches!(profile, Profile::Core { .. });
            assert_eq!(has(&args, TPM_DEVICE), core, "{profile:?}");
            if core {
                let at = args.iter().position(|a| a == "--dev-bind-try").unwrap();
                assert_eq!(args[at + 1], TPM_DEVICE);
                assert!(
                    args.iter().position(|a| a == "--dev").unwrap() < at,
                    "the TPM goes on top of the minimal /dev"
                );
            }
        }
    }

    #[test]
    fn every_profile_is_isolated() {
        let profiles = [
            Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![],
            },
            Profile::Core {
                data_dir: "/d".into(),
            },
            Profile::Ui {
                wayland_display: "wayland-1".into(),
            },
            kpclientd(),
            tor(),
            Profile::Relay {
                socket_dir: "/r".into(),
            },
            Profile::TorCtl {
                control_dir: "/c".into(),
            },
        ];
        for profile in &profiles {
            let args = bwrap_args(profile, Path::new("/bin-dir"), &[]);
            for flag in [
                "--unshare-all",
                "--die-with-parent",
                "--new-session",
                "--clearenv",
            ] {
                assert!(has(&args, flag), "{profile:?} is missing {flag}");
            }
        }
    }

    fn tor() -> Profile {
        Profile::Tor {
            data_dir: "/st/tor".into(),
            socket_dir: "/run/user/1000/purple/tor-1".into(),
            control_dir: "/run/user/1000/purple/torctl-1".into(),
            torrc: "/run/user/1000/purple/tor-1.rc".into(),
        }
    }

    #[test]
    fn tor_gets_network_its_dirs_its_torrc_and_purples_seccomp() {
        let args = bwrap_args(&tor(), Path::new("/b"), &["-f", TOR_RC]);
        assert!(has(&args, "--share-net"));
        assert!(has(&args, "/st/tor") && has(&args, TOR_DATA_DIR));
        assert!(has(&args, "/run/user/1000/purple/tor-1") && has(&args, TOR_SOCKET_DIR));
        assert!(has(&args, TOR_RC));
        assert_eq!(args.iter().filter(|a| *a == "--add-seccomp-fd").count(), 2);
        assert_eq!(args[args.len() - 3], "/usr/bin/tor");
    }

    #[test]
    fn net_in_tor_mode_has_sockets_but_no_network() {
        let net = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![
                    ("/t".into(), TOR_SOCKET_DIR),
                    ("/r".into(), RELAY_SOCKET_DIR),
                ],
            },
            Path::new("/b"),
            &[],
        );
        assert!(!has(&net, "--share-net"));
        for (host, inside) in [("/t", TOR_SOCKET_DIR), ("/r", RELAY_SOCKET_DIR)] {
            let at = net.iter().position(|a| a == host).unwrap();
            assert_eq!(net[at - 1], "--ro-bind");
            assert_eq!(net[at + 1], inside);
        }
    }

    #[test]
    fn relay_gets_network_and_its_socket_dir_only() {
        let relay = bwrap_args(
            &Profile::Relay {
                socket_dir: "/r".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(has(&relay, "--share-net"));
        assert!(has(&relay, RELAY_SOCKET_DIR));
        assert!(!has(&relay, TOR_SOCKET_DIR));
    }

    #[test]
    fn only_net_gets_the_network() {
        let net = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![],
            },
            Path::new("/b"),
            &[],
        );
        let core = bwrap_args(
            &Profile::Core {
                data_dir: "/d".into(),
            },
            Path::new("/b"),
            &[],
        );
        let ui = bwrap_args(
            &Profile::Ui {
                wayland_display: "wayland-1".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(has(&net, "--share-net"));
        assert!(!has(&core, "--share-net"));
        assert!(!has(&ui, "--share-net"));
        // The daemons that do the networking for purple-net get it too.
        for daemon in [
            tor(),
            Profile::Relay {
                socket_dir: "/r".into(),
            },
            kpclientd(),
        ] {
            assert!(has(
                &bwrap_args(&daemon, Path::new("/b"), &[]),
                "--share-net"
            ));
        }
    }

    #[test]
    fn ui_gets_wayland_display_but_nothing_to_bind() {
        let ui = bwrap_args(
            &Profile::Ui {
                wayland_display: "wayland-1".into(),
            },
            Path::new("/b"),
            &[],
        );
        let core = bwrap_args(
            &Profile::Core {
                data_dir: "/d".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(has(&ui, "WAYLAND_DISPLAY"));
        assert!(!has(&ui, "--bind"));
        assert!(!has(&core, "WAYLAND_DISPLAY"));
    }

    #[test]
    fn binary_and_args_come_last() {
        let args = bwrap_args(
            &Profile::Core {
                data_dir: "/d".into(),
            },
            Path::new("/b"),
            &["--no-ui"],
        );
        assert_eq!(args[args.len() - 2], "/app/purple-core");
        assert_eq!(args[args.len() - 1], "--no-ui");
    }

    #[test]
    fn passed_fd_reaches_the_child_at_its_target() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut cmd = Command::new("/usr/bin/test");
        cmd.args(["-S", "/dev/fd/7"]);
        pass_fds(&mut cmd, &[(theirs.as_raw_fd(), 7)]).unwrap();
        assert!(cmd.status().unwrap().success());
        drop(ours);
    }

    #[test]
    fn unpassed_fds_do_not_leak() {
        let (_ours, _theirs) = UnixStream::pair().unwrap();
        let mut cmd = Command::new("/usr/bin/test");
        cmd.args(["-e", "/dev/fd/7"]);
        pass_fds(&mut cmd, &[]).unwrap();
        assert!(!cmd.status().unwrap().success());
    }

    #[test]
    fn torctl_sees_tors_control_dir_and_nothing_else() {
        let args = bwrap_args(
            &Profile::TorCtl {
                control_dir: "/c".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(!has(&args, "--share-net"));
        let at = args.iter().position(|a| a == "/c").unwrap();
        assert_eq!(args[at - 1], "--ro-bind");
        assert_eq!(args[at + 1], TORCTL_SOCKET_DIR);
        assert!(!has(&args, TOR_SOCKET_DIR) && !has(&args, RELAY_SOCKET_DIR));
        assert_eq!(args[args.len() - 1], "/app/purple-torctl");
    }

    #[test]
    fn tor_gets_both_socket_dirs_and_net_only_the_socks_one() {
        let tor = bwrap_args(&tor(), Path::new("/b"), &[]);
        assert!(has(&tor, TOR_SOCKET_DIR) && has(&tor, TORCTL_SOCKET_DIR));
        let net = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                sockets: vec![
                    ("/t".into(), TOR_SOCKET_DIR),
                    ("/r".into(), RELAY_SOCKET_DIR),
                ],
            },
            Path::new("/b"),
            &[],
        );
        assert!(!has(&net, TORCTL_SOCKET_DIR));
    }

    #[test]
    fn net_cannot_see_the_control_socket_or_an_unstarted_relay() {
        if !bwrap_works() {
            return;
        }
        let base = std::env::temp_dir().join(format!("purple-net-sees-{}", std::process::id()));
        let (socks, relay, ctl) = (base.join("tor"), base.join("relay"), base.join("torctl"));
        for d in [&socks, &relay, &ctl] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(ctl.join("control.sock"), b"").unwrap();
        let mut args = bwrap_args(
            &Profile::Net {
                state_dir: base.clone(),
                sockets: vec![(socks, TOR_SOCKET_DIR), (relay, RELAY_SOCKET_DIR)],
            },
            Path::new("/usr/bin"),
            &[],
        );
        args.pop(); // the purple-net path
        let sees = |path: &str| {
            let mut probe = args.clone();
            probe.extend(["/usr/bin/test", "-e", path].map(OsString::from));
            Command::new("bwrap")
                .args(&probe)
                .status()
                .unwrap()
                .success()
        };
        assert!(!sees(TOR_CONTROL));
        assert!(!sees(RELAY_SOCKET));
        assert!(sees(TOR_SOCKET_DIR));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
