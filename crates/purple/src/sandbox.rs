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
const CORE_DATA_DIR: &str = "/data";
/// Runtime dir and socket name `purple-ui` sees inside its sandbox.
const UI_RUNTIME_DIR: &str = "/run/purple";
const UI_WAYLAND_NAME: &str = "wayland-0";

const MAX_PASSED_FDS: usize = 4;

/// What one purple process is allowed to reach.
#[derive(Debug)]
pub(crate) enum Profile {
    /// Network access plus its own state directory.
    Net { state_dir: PathBuf },
    /// Its own data directory. No network, no display.
    Core { data_dir: PathBuf },
    /// The Wayland socket only. No network, nothing writable.
    Ui { wayland_socket: PathBuf },
}

impl Profile {
    pub(crate) const fn binary(&self) -> &'static str {
        match self {
            Self::Net { .. } => "purple-net",
            Self::Core { .. } => "purple-core",
            Self::Ui { .. } => "purple-ui",
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
        Profile::Net { state_dir } => {
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
            out.extend(["--bind".into(), state_dir.into(), NET_STATE_DIR.into()]);
        }
        Profile::Core { data_dir } => {
            out.extend(["--bind".into(), data_dir.into(), CORE_DATA_DIR.into()]);
        }
        Profile::Ui { wayland_socket } => {
            let inner = Path::new(UI_RUNTIME_DIR).join(UI_WAYLAND_NAME);
            out.extend(["--ro-bind".into(), wayland_socket.into(), inner.into()]);
            out.extend(["--setenv", "XDG_RUNTIME_DIR", UI_RUNTIME_DIR].map(OsString::from));
            out.extend(["--setenv", "WAYLAND_DISPLAY", UI_WAYLAND_NAME].map(OsString::from));
        }
    }

    out.extend([
        "--chdir".into(),
        "/".into(),
        Path::new(APP_DIR).join(profile.binary()).into(),
    ]);
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
    if let Profile::Ui { wayland_socket } = profile {
        cmd.env("WAYLAND_DISPLAY", wayland_socket);
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

    #[test]
    fn every_profile_is_isolated() {
        let profiles = [
            Profile::Net {
                state_dir: "/s".into(),
            },
            Profile::Core {
                data_dir: "/d".into(),
            },
            Profile::Ui {
                wayland_socket: "/w".into(),
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

    #[test]
    fn only_net_gets_the_network() {
        let net = bwrap_args(
            &Profile::Net {
                state_dir: "/s".into(),
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
                wayland_socket: "/w".into(),
            },
            Path::new("/b"),
            &[],
        );
        assert!(has(&net, "--share-net"));
        assert!(!has(&core, "--share-net"));
        assert!(!has(&ui, "--share-net"));
    }

    #[test]
    fn only_ui_gets_the_wayland_socket() {
        let ui = bwrap_args(
            &Profile::Ui {
                wayland_socket: "/w".into(),
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
        assert!(has(&ui, "/w"));
        assert!(has(&ui, "WAYLAND_DISPLAY"));
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
