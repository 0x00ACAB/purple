//! purple launcher: starts `purple-net`, `purple-core` and `purple-ui`, each in its own
//! bubblewrap sandbox, connected only by the sockets passed in here.
//!
//! Usage: `purple [--no-ui] [--dev-provider <addr>]`. `--no-ui` runs the self-test instead
//! of the TUI. `--dev-provider` points `purple-net` at a local `purple-devprovider`.

mod sandbox;

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};

use purple_ipc::{CORE_NET_FD, CORE_UI_FD, NET_CORE_FD, UI_CORE_FD};
use sandbox::Profile;

const USAGE: &str = "usage: purple [--no-ui] [--dev-provider <addr>]";

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

#[derive(Debug, Default)]
struct Options {
    no_ui: bool,
    dev_provider: Option<String>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-ui" => options.no_ui = true,
            "--dev-provider" => {
                options.dev_provider = Some(args.next().ok_or_else(|| io::Error::other(USAGE))?);
            }
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    Ok(options)
}

/// Returns whether every child exited successfully.
fn run() -> io::Result<bool> {
    let options = parse_args(std::env::args().skip(1))?;
    // purple refuses to run outside a Wayland session, where X11 clients can read keystrokes.
    let wayland_display = if options.no_ui {
        None
    } else {
        Some(std::env::var_os("WAYLAND_DISPLAY").ok_or_else(|| {
            io::Error::other(
                "WAYLAND_DISPLAY is not set. purple only runs in a Wayland session \
                 (use --no-ui to run the self-test without the TUI)",
            )
        })?)
    };
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

    let state_root = private_dir(&xdg_dir("XDG_STATE_HOME", ".local/state")?.join("purple"))?;
    let state_dir = private_dir(&state_root.join("net"))?;
    let data_dir = private_dir(&xdg_dir("XDG_DATA_HOME", ".local/share")?.join("purple/core"))?;
    // While the TUI owns the terminal, core and net log to a file instead.
    let log = match wayland_display {
        Some(_) => Some(open_log(&state_root.join("purple.log"))?),
        None => None,
    };

    let net_args: Vec<&str> = options
        .dev_provider
        .as_deref()
        .map_or_else(Vec::new, |addr| vec!["--dev-provider", addr]);

    let mut children = Vec::new();
    let (core_net, net_core) = UnixStream::pair()?;
    children.push(spawn(
        &Profile::Net { state_dir },
        bin_dir,
        sandboxed,
        &net_args,
        &[(net_core.as_raw_fd(), NET_CORE_FD)],
        Background(log.as_ref()),
    )?);

    match wayland_display {
        None => {
            children.push(spawn(
                &Profile::Core { data_dir },
                bin_dir,
                sandboxed,
                &["--no-ui"],
                &[(core_net.as_raw_fd(), CORE_NET_FD)],
                Background(None),
            )?);
        }
        Some(wayland_display) => {
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
                Background(log.as_ref()),
            )?);
            children.push(spawn_ui(wayland_display, bin_dir, sandboxed, &ui_core)?);
        }
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

/// Stdio for a process that doesn't own the terminal: no stdin, and stdout/stderr to `log`
/// when given (otherwise inherited).
#[derive(Clone, Copy)]
struct Background<'a>(Option<&'a File>);

fn spawn(
    profile: &Profile,
    bin_dir: &Path,
    sandboxed: bool,
    args: &[&str],
    fds: &[(RawFd, RawFd)],
    background: Background<'_>,
) -> io::Result<(String, Child)> {
    let mut cmd = sandbox::command(profile, bin_dir, sandboxed, args);
    sandbox::pass_fds(&mut cmd, fds)?;
    cmd.stdin(Stdio::null());
    if let Background(Some(log)) = background {
        cmd.stdout(log.try_clone()?).stderr(log.try_clone()?);
    }
    Ok((profile.binary().to_owned(), cmd.spawn()?))
}

/// `purple-ui` inherits the terminal.
fn spawn_ui(
    wayland_display: OsString,
    bin_dir: &Path,
    sandboxed: bool,
    ui_core: &UnixStream,
) -> io::Result<(String, Child)> {
    let profile = Profile::Ui { wayland_display };
    let mut cmd = sandbox::command(&profile, bin_dir, sandboxed, &[]);
    sandbox::pass_fds(&mut cmd, &[(ui_core.as_raw_fd(), UI_CORE_FD)])?;
    Ok((profile.binary().to_owned(), cmd.spawn()?))
}

fn open_log(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> io::Result<Options> {
        parse_args(args.iter().map(|&a| a.to_owned()))
    }

    #[test]
    fn parses_flags() {
        assert!(!parse(&[]).unwrap().no_ui);
        assert!(parse(&["--no-ui"]).unwrap().no_ui);
        let opts = parse(&["--dev-provider", "127.0.0.1:7878", "--no-ui"]).unwrap();
        assert_eq!(opts.dev_provider.as_deref(), Some("127.0.0.1:7878"));
        assert!(opts.no_ui);
        assert!(parse(&["--dev-provider"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
    }
}
