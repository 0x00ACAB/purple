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
/// Fds bwrap reads `kpclientd`'s seccomp filters from.
pub(crate) const KP_SECCOMP_FDS: [RawFd; 2] = [10, 11];

const MAX_PASSED_FDS: usize = 4;

/// What one purple process is allowed to reach.
#[derive(Debug)]
pub(crate) enum Profile {
    /// Network access plus its own state directory, and `kpclientd`'s socket directory
    /// (read-only) when that transport is in use.
    Net {
        state_dir: PathBuf,
        kp_socket_dir: Option<PathBuf>,
    },
    /// Its own data directory. No network, no display.
    Core { data_dir: PathBuf },
    /// The terminal it inherits only. No network, nothing writable. `WAYLAND_DISPLAY` is
    /// passed through so `purple-ui` can refuse to run outside a Wayland session.
    Ui { wayland_display: OsString },
    /// Katzenpost's client daemon: network access, its config read-only, and the directory
    /// it creates its socket in. purple can't modify it, so bwrap installs purple's seccomp
    /// filters on it (from [`KP_SECCOMP_FDS`]).
    KpClientd {
        binary: PathBuf,
        config: PathBuf,
        socket_dir: PathBuf,
    },
}

impl Profile {
    pub(crate) const fn binary(&self) -> &'static str {
        match self {
            Self::Net { .. } => "purple-net",
            Self::Core { .. } => "purple-core",
            Self::Ui { .. } => "purple-ui",
            Self::KpClientd { .. } => "kpclientd",
        }
    }

    /// The program to run inside the sandbox.
    fn exec_path(&self) -> PathBuf {
        match self {
            Self::KpClientd { .. } => PathBuf::from(KP_BINARY),
            Self::Net { .. } | Self::Core { .. } | Self::Ui { .. } => {
                Path::new(APP_DIR).join(self.binary())
            }
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
        Profile::Net {
            state_dir,
            kp_socket_dir,
        } => {
            if let Some(dir) = kp_socket_dir {
                // kpclientd does the networking; purple-net gets only its socket and no
                // network namespace of its own.
                out.extend(["--ro-bind".into(), dir.into(), KP_SOCKET_DIR.into()]);
            } else {
                out.extend(
                    [
                        "--share-net",
                        "--ro-bind-try",
                        "/etc/resolv.conf",
                        "/etc/resolv.conf",
                    ]
                    .map(OsString::from),
                );
                out.extend(["--ro-bind-try", "/etc/ssl", "/etc/ssl"].map(OsString::from));
                out.extend(
                    [
                        "--ro-bind-try",
                        "/etc/ca-certificates",
                        "/etc/ca-certificates",
                    ]
                    .map(OsString::from),
                );
            }
            out.extend(["--bind".into(), state_dir.into(), NET_STATE_DIR.into()]);
        }
        Profile::Core { data_dir } => {
            out.extend(["--bind".into(), data_dir.into(), CORE_DATA_DIR.into()]);
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
            for fd in KP_SECCOMP_FDS {
                out.extend(["--add-seccomp-fd".into(), fd.to_string().into()]);
            }
        }
    }

    out.extend(["--chdir".into(), "/".into(), profile.exec_path().into()]);
    out.extend(args.iter().map(OsString::from));
    out
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
                kp_socket_dir: Some("/run/user/1000/purple/kp".into()),
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
                kp_socket_dir: None,
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
    fn every_profile_is_isolated() {
        let profiles = [
            Profile::Net {
                state_dir: "/s".into(),
                kp_socket_dir: None,
            },
            Profile::Core {
                data_dir: "/d".into(),
            },
            Profile::Ui {
                wayland_display: "wayland-1".into(),
            },
            kpclientd(),
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

    #[test]
    fn only_net_gets_the_network() {
        let net = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
                kp_socket_dir: None,
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
}
