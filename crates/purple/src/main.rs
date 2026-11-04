//! purple launcher: starts `purple-net`, `purple-core` and `purple-ui`, each in its own
//! bubblewrap sandbox, connected only by the sockets passed in here.

mod sandbox;

use std::fs::DirBuilder;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode};

use purple_ipc::{CORE_NET_FD, CORE_UI_FD, NET_CORE_FD, UI_CORE_FD};
use sandbox::Profile;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("purple: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Returns whether every child exited successfully.
fn run() -> io::Result<bool> {
    let no_ui = std::env::args().any(|arg| arg == "--no-ui");
    let exe = std::env::current_exe()?;
    let bin_dir = exe
        .parent()
        .ok_or_else(|| io::Error::other("launcher has no parent directory"))?;

    let sandboxed = sandbox::bwrap_works();
    if !sandboxed {
        eprintln!(
            "purple: warning: bubblewrap can't create a sandbox here (unprivileged user \
             namespaces may be disabled). Running with in-process hardening only."
        );
    }

    let state_dir = private_dir(&xdg_dir("XDG_STATE_HOME", ".local/state")?.join("purple/net"))?;
    let data_dir = private_dir(&xdg_dir("XDG_DATA_HOME", ".local/share")?.join("purple/core"))?;

    let mut children = Vec::new();
    let (core_net, net_core) = UnixStream::pair()?;
    children.push(spawn(
        &Profile::Net { state_dir },
        bin_dir,
        sandboxed,
        &[],
        &[(net_core.as_raw_fd(), NET_CORE_FD)],
    )?);

    if no_ui {
        let core_fds = [(core_net.as_raw_fd(), CORE_NET_FD)];
        children.push(spawn(
            &Profile::Core { data_dir },
            bin_dir,
            sandboxed,
            &["--no-ui"],
            &core_fds,
        )?);
    } else {
        let wayland_socket = wayland_socket()?;
        let (core_ui, ui_core) = UnixStream::pair()?;
        let core_fds = [
            (core_ui.as_raw_fd(), CORE_UI_FD),
            (core_net.as_raw_fd(), CORE_NET_FD),
        ];
        children.push(spawn(
            &Profile::Core { data_dir },
            bin_dir,
            sandboxed,
            &[],
            &core_fds,
        )?);
        let ui_fds = [(ui_core.as_raw_fd(), UI_CORE_FD)];
        children.push(spawn(
            &Profile::Ui { wayland_socket },
            bin_dir,
            sandboxed,
            &[],
            &ui_fds,
        )?);
    }
    // The launcher's copies of the sockets close here, so each child sees EOF when its peer
    // exits.
    drop((core_net, net_core));

    let mut all_ok = true;
    for (name, mut child) in children {
        let status = child.wait()?;
        if !status.success() {
            eprintln!("purple: {name} exited with {status}");
            all_ok = false;
        }
    }
    Ok(all_ok)
}

fn spawn(
    profile: &Profile,
    bin_dir: &Path,
    sandboxed: bool,
    args: &[&str],
    fds: &[(RawFd, RawFd)],
) -> io::Result<(String, Child)> {
    let mut cmd = sandbox::command(profile, bin_dir, sandboxed, args);
    sandbox::pass_fds(&mut cmd, fds)?;
    Ok((profile.binary().to_owned(), cmd.spawn()?))
}

/// The Wayland socket to hand to `purple-ui`. purple refuses to run on X11.
fn wayland_socket() -> io::Result<PathBuf> {
    let display = std::env::var_os("WAYLAND_DISPLAY").ok_or_else(|| {
        io::Error::other("WAYLAND_DISPLAY is not set. purple only runs on Wayland (use --no-ui to run without a window)")
    })?;
    let display = PathBuf::from(display);
    let socket = if display.is_absolute() {
        display
    } else {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR is not set"))?;
        PathBuf::from(runtime).join(display)
    };
    if !socket.exists() {
        return Err(io::Error::other(format!(
            "Wayland socket {} does not exist",
            socket.display()
        )));
    }
    Ok(socket)
}

/// `$var` if it's set to an absolute path, else `$HOME/fallback`.
fn xdg_dir(var: &str, fallback: &str) -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
    {
        return Ok(dir);
    }
    let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is not set"))?;
    Ok(PathBuf::from(home).join(fallback))
}

/// Create `dir` (and parents) readable only by the user, and return it.
fn private_dir(dir: &Path) -> io::Result<PathBuf> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    Ok(dir.to_path_buf())
}
