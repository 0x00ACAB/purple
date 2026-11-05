//! purple launcher: starts `purple-net`, `purple-core` and `purple-ui`, each in its own
//! bubblewrap sandbox, connected only by the sockets passed in here.
//!
//! Usage: `purple [--no-ui] [--dev-provider <addr>] [--send-interval-ms <ms>]
//! [--kpclientd <binary> --kp-config <file>]`. `--no-ui` runs the self-test instead of the
//! TUI. `--dev-provider` points `purple-net` at a local `purple-devprovider`.
//! `--send-interval-ms` sets the mean gap between packets in the cover stream (default
//! 1000; the self-test uses 50 unless told otherwise). `--kpclientd` and `--kp-config` also
//! run Katzenpost's client daemon in a fifth sandbox, with its socket shared read-only with
//! `purple-net`, which then stores boxes on Pigeonhole and has no network of its own.

mod sandbox;

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use purple_harden::sandbox::{Network, seccomp_programs};
use purple_ipc::{CORE_NET_FD, CORE_UI_FD, NET_CORE_FD, UI_CORE_FD};
use sandbox::Profile;

const USAGE: &str = "usage: purple [--no-ui] [--dev-provider <addr>] [--send-interval-ms <ms>] \
                     [--kpclientd <binary> --kp-config <file>]";
/// kpclientd's socket, in the directory the launcher makes for it.
const KP_SOCKET_NAME: &str = "kpclientd.sock";
/// How long kpclientd may take to open its socket, and how often to look.
const KP_SOCKET_WAIT: Duration = Duration::from_secs(30);
const KP_SOCKET_POLL: Duration = Duration::from_millis(50);
/// Mean send gap for the self-test, so it finishes in seconds.
const SELF_TEST_SEND_INTERVAL_MS: &str = "50";

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
    send_interval_ms: Option<String>,
    kpclientd: Option<PathBuf>,
    kp_config: Option<PathBuf>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<Options> {
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-ui" => options.no_ui = true,
            "--dev-provider" => {
                options.dev_provider = Some(args.next().ok_or_else(|| io::Error::other(USAGE))?);
            }
            "--send-interval-ms" => {
                options.send_interval_ms =
                    Some(args.next().ok_or_else(|| io::Error::other(USAGE))?);
            }
            "--kpclientd" => {
                options.kpclientd =
                    Some(args.next().ok_or_else(|| io::Error::other(USAGE))?.into());
            }
            "--kp-config" => {
                options.kp_config =
                    Some(args.next().ok_or_else(|| io::Error::other(USAGE))?.into());
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

    if options.dev_provider.is_some() && options.kpclientd.is_some() {
        return Err(io::Error::other(
            "--dev-provider and --kpclientd don't go together",
        ));
    }
    let kp = prepare_kpclientd(options.kpclientd, options.kp_config, sandboxed)?;

    let state_root = private_dir(&xdg_dir("XDG_STATE_HOME", ".local/state")?.join("purple"))?;
    let state_dir = private_dir(&state_root.join("net"))?;
    let data_dir = private_dir(&xdg_dir("XDG_DATA_HOME", ".local/share")?.join("purple/core"))?;
    // While the TUI owns the terminal, core and net log to a file instead.
    let log = match wayland_display {
        Some(_) => Some(open_log(&state_root.join("purple.log"))?),
        None => None,
    };

    let net_args = net_args(
        options.dev_provider.as_deref(),
        kp.is_some(),
        options.send_interval_ms.as_deref(),
        options.no_ui,
    );

    let kp_child = match &kp {
        Some((binary, config, socket_dir)) => {
            let mut child = spawn_kpclientd(
                binary,
                config,
                socket_dir,
                bin_dir,
                Background(log.as_ref()),
            )?;
            wait_for_socket(&socket_dir.join(KP_SOCKET_NAME), &mut child.1)?;
            Some(child)
        }
        None => None,
    };

    let mut children = Vec::new();
    let (core_net, net_core) = UnixStream::pair()?;
    children.push(spawn(
        &Profile::Net {
            state_dir,
            kp_socket_dir: kp.map(|(_, _, socket_dir)| socket_dir),
        },
        bin_dir,
        sandboxed,
        &net_args,
        &[(net_core.as_raw_fd(), NET_CORE_FD)],
        Background(log.as_ref()),
    )?);

    children.extend(spawn_core_and_ui(
        wayland_display,
        data_dir,
        bin_dir,
        sandboxed,
        &core_net,
        log.as_ref(),
    )?);
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
    // kpclientd doesn't exit on its own. Killing its bwrap tears down the whole sandbox.
    if let Some((_, mut child)) = kp_child {
        child.kill().ok();
        child.wait()?;
    }
    Ok(all_ok)
}

/// Start `purple-core`, and `purple-ui` when there's a display. With no display, core runs
/// its self-test.
fn spawn_core_and_ui(
    wayland_display: Option<OsString>,
    data_dir: PathBuf,
    bin_dir: &Path,
    sandboxed: bool,
    core_net: &UnixStream,
    log: Option<&File>,
) -> io::Result<Vec<(String, Child)>> {
    let mut out = Vec::new();
    match wayland_display {
        None => {
            out.push(spawn(
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
            // Inside the sandbox the data directory is mounted at a fixed path.
            let data_arg = if sandboxed {
                sandbox::CORE_DATA_DIR.to_owned()
            } else {
                data_dir
                    .to_str()
                    .ok_or_else(|| io::Error::other("data directory path is not UTF-8"))?
                    .to_owned()
            };
            out.push(spawn(
                &Profile::Core { data_dir },
                bin_dir,
                sandboxed,
                &["--data-dir", &data_arg],
                &core_fds,
                Background(log),
            )?);
            out.push(spawn_ui(wayland_display, bin_dir, sandboxed, &ui_core)?);
        }
    }
    Ok(out)
}

/// A `kpclientd` to run: its binary, its config, and the private directory for its socket.
type KpSetup = (PathBuf, PathBuf, PathBuf);

/// Check `--kpclientd`/`--kp-config` and prepare the socket directory.
fn prepare_kpclientd(
    binary: Option<PathBuf>,
    config: Option<PathBuf>,
    sandboxed: bool,
) -> io::Result<Option<KpSetup>> {
    let (binary, config) = match (binary, config) {
        (Some(binary), Some(config)) => (binary, config),
        (None, None) => return Ok(None),
        _ => return Err(io::Error::other("--kpclientd and --kp-config go together")),
    };
    if !sandboxed {
        return Err(io::Error::other(
            "purple won't run kpclientd without bubblewrap around it",
        ));
    }
    check_kp_config(&fs::read_to_string(&config)?)?;
    let socket_dir = private_dir(&runtime_dir()?.join("purple/kp"))?;
    // A socket left by an earlier run would make kpclientd's bind fail.
    match fs::remove_file(socket_dir.join(KP_SOCKET_NAME)) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        Ok(()) | Err(_) => {}
    }
    Ok(Some((binary, config, socket_dir)))
}

/// Wait until kpclientd has made its socket, so `purple-net` can connect at once.
fn wait_for_socket(path: &Path, kpclientd: &mut Child) -> io::Result<()> {
    let start = Instant::now();
    while !path.exists() {
        if let Some(status) = kpclientd.try_wait()? {
            return Err(io::Error::other(format!("kpclientd exited with {status}")));
        }
        if start.elapsed() >= KP_SOCKET_WAIT {
            return Err(io::Error::other("kpclientd didn't open its socket in time"));
        }
        thread::sleep(KP_SOCKET_POLL);
    }
    Ok(())
}

/// Arguments for `purple-net`. With `katzenpost`, it reaches kpclientd's socket where
/// its sandbox mounts it.
fn net_args<'a>(
    dev_provider: Option<&'a str>,
    katzenpost: bool,
    send_interval_ms: Option<&'a str>,
    no_ui: bool,
) -> Vec<&'a str> {
    let mut args = Vec::new();
    if let Some(addr) = dev_provider {
        args.extend(["--dev-provider", addr]);
    }
    if katzenpost {
        args.extend(["--katzenpost", sandbox::KP_SOCKET]);
    }
    let send_interval = match (send_interval_ms, no_ui) {
        (Some(ms), _) => Some(ms),
        (None, true) => Some(SELF_TEST_SEND_INTERVAL_MS),
        (None, false) => None,
    };
    if let Some(ms) = send_interval {
        args.extend(["--send-interval-ms", ms]);
    }
    args
}

/// Run Katzenpost's client daemon sandboxed, with purple's seccomp filters installed by
/// bwrap from pipes.
fn spawn_kpclientd(
    binary: &Path,
    config: &Path,
    socket_dir: &Path,
    bin_dir: &Path,
    background: Background<'_>,
) -> io::Result<(String, Child)> {
    let profile = Profile::KpClientd {
        binary: binary.to_owned(),
        config: config.to_owned(),
        socket_dir: socket_dir.to_owned(),
    };
    let mut cmd = sandbox::command(&profile, bin_dir, true, &["-c", sandbox::KP_CONFIG]);
    let mut readers = Vec::new();
    for program in seccomp_programs(Network::Allowed)? {
        let (reader, mut writer) = io::pipe()?;
        writer.write_all(&program)?;
        readers.push(reader);
    }
    let fds: Vec<(RawFd, RawFd)> = readers
        .iter()
        .map(AsRawFd::as_raw_fd)
        .zip(sandbox::KP_SECCOMP_FDS)
        .collect();
    sandbox::pass_fds(&mut cmd, &fds)?;
    cmd.stdin(Stdio::null());
    if let Background(Some(log)) = background {
        cmd.stdout(log.try_clone()?).stderr(log.try_clone()?);
    }
    let child = cmd.spawn()?;
    drop(readers);
    Ok((profile.binary().to_owned(), child))
}

/// Refuse a `kpclientd` config that wouldn't listen where `purple-net` connects, or that
/// also listens on an abstract socket, which any local process could connect to.
fn check_kp_config(text: &str) -> io::Result<()> {
    if !text.contains(sandbox::KP_SOCKET) {
        return Err(io::Error::other(format!(
            "kpclientd config must set [Listen.Unix] Address = \"{}\"",
            sandbox::KP_SOCKET
        )));
    }
    let abstract_listen = text
        .lines()
        .map(str::trim)
        .any(|line| line.starts_with("Address") && line.contains("\"@"));
    if abstract_listen {
        return Err(io::Error::other(
            "kpclientd config listens on an abstract socket (\"@...\"); remove it",
        ));
    }
    Ok(())
}

/// `$XDG_RUNTIME_DIR`, which must be set to an absolute path.
fn runtime_dir() -> io::Result<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR is not set"))
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
    fn kp_config_must_use_purples_socket_and_no_abstract_one() {
        let good = "[Listen]\n  [Listen.Unix]\n    Addresses = [\"/run/kp/kpclientd.sock\"]\n";
        assert!(check_kp_config(good).is_ok());
        let wrong_path = "[Listen.Unix]\n    Addresses = [\"/tmp/k.sock\"]\n";
        assert!(check_kp_config(wrong_path).is_err());
        let with_abstract = format!("{good}    Address = \"@katzenpost\"\n");
        assert!(check_kp_config(&with_abstract).is_err());
    }

    #[test]
    fn parses_flags() {
        assert!(!parse(&[]).unwrap().no_ui);
        assert!(parse(&["--no-ui"]).unwrap().no_ui);
        let opts = parse(&["--dev-provider", "127.0.0.1:7878", "--no-ui"]).unwrap();
        assert_eq!(opts.dev_provider.as_deref(), Some("127.0.0.1:7878"));
        assert!(opts.no_ui);
        assert!(parse(&["--dev-provider"]).is_err());
        let kp = parse(&["--kpclientd", "/k", "--kp-config", "/c"]).unwrap();
        assert_eq!(kp.kpclientd.as_deref(), Some(Path::new("/k")));
        assert_eq!(kp.kp_config.as_deref(), Some(Path::new("/c")));
        let fast = parse(&["--send-interval-ms", "20"]).unwrap();
        assert_eq!(fast.send_interval_ms.as_deref(), Some("20"));
        assert!(parse(&["--bogus"]).is_err());
    }
}
