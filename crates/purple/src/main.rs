//! purple launcher: starts `purple-subspace`, `purple-data` and `purple-lcars`, each in its own
//! bubblewrap sandbox, connected only by the sockets passed in here.
//!
//! Usage: `purple [--no-ui] [--store-config <file>] [--dev-provider <addr>]
//! [--send-interval-ms <ms>] [--kpclientd <binary> --kp-config <file>]`. `--no-ui` runs the
//! self-test instead of the TUI.
//!
//! The TUI uses the box store named in the store config (`--store-config`, by default
//! `$XDG_CONFIG_HOME/purple/store.conf`), reached through C tor in its own sandbox, and,
//! if the config has a direct port and the user asks for it, through purple-transporter, which
//! the launcher starts only when core asks. purple-cloak drives tor's control port. The
//! self-test uses an in-memory network unless given a store config. `--dev-provider` points
//! `purple-subspace` at a local `purple-holodeck`. `--send-interval-ms` sets the mean gap
//! between packets in the cover stream (default 500 over Tor, 1000 otherwise; the self-test
//! uses 50 unless told otherwise). `--kpclientd` and `--kp-config` run Katzenpost's client
//! daemon instead of tor, with its socket shared read-only with `purple-subspace`, which then
//! stores boxes on Pigeonhole.

mod sandbox;
mod store_config;
mod torrc;

use store_config::{StoreConfig, parse_store_config};

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ExitCode, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use purple_combadge::torctl::LauncherMsg;
use purple_combadge::{
    CORE_LAUNCHER_FD, CORE_NET_FD, CORE_TORCTL_FD, CORE_UI_FD, NET_CORE_FD, TORCTL_CORE_FD,
    UI_CORE_FD,
};
use purple_shields::sandbox::{Network, seccomp_programs};
use sandbox::Profile;

const USAGE: &str = "usage: purple [--no-ui] [--store-config <file>] [--dev-provider <addr>] \
                     [--send-interval-ms <ms>] [--kpclientd <binary> --kp-config <file>]";
/// kpclientd's socket, in the directory the launcher makes for it.
const KP_SOCKET_NAME: &str = "kpclientd.sock";
/// tor's SOCKS socket and purple-transporter's socket, in the directories made for them.
const TOR_SOCKS_NAME: &str = "socks.sock";
const RELAY_SOCKET_NAME: &str = "relay.sock";
/// How long a daemon may take to open its socket, and how often to look.
const SOCKET_WAIT: Duration = Duration::from_secs(30);
const SOCKET_POLL: Duration = Duration::from_millis(50);
/// Mean send gap over Tor: 2 packets a second.
const TOR_SEND_INTERVAL_MS: &str = "500";
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
    store_config: Option<PathBuf>,
}

/// Where boxes go.
#[derive(Debug)]
enum Mode {
    /// An in-memory network only this run can see (the self-test).
    Memory,
    /// A local `purple-holodeck`.
    Dev(String),
    /// Pigeonhole, through kpclientd.
    Katzenpost(KpSetup),
    /// purple's own store, through tor.
    Tor(StoreConfig),
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
            "--store-config" => {
                options.store_config =
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

    let mode = choose_mode(
        options.dev_provider,
        options.kpclientd,
        options.kp_config,
        options.store_config,
        options.no_ui,
        sandboxed,
    )?;

    let state_root = private_dir(&xdg_dir("XDG_STATE_HOME", ".local/state")?.join("purple"))?;
    let state_dir = private_dir(&state_root.join("net"))?;
    let data_dir = private_dir(&xdg_dir("XDG_DATA_HOME", ".local/share")?.join("purple/core"))?;
    // While the TUI owns the terminal, core and net log to a file instead.
    let log = match wayland_display {
        Some(_) => Some(open_log(&state_root.join("purple.log"))?),
        None => None,
    };
    let background = Background(log.as_ref());

    let net_owned = net_args(&mode, options.send_interval_ms.as_deref(), options.no_ui);
    let mut daemons = Daemons::default();
    let (sockets, tor_dirs) = match &mode {
        Mode::Katzenpost(kp) => (
            start_kpclientd(kp, bin_dir, background, &mut daemons)?,
            None,
        ),
        Mode::Tor(config) => {
            let dirs = start_tor(&state_root, bin_dir, background, &mut daemons)?;
            (dirs.net_sockets.clone(), Some((config, dirs)))
        }
        Mode::Memory | Mode::Dev(_) => (Vec::new(), None),
    };
    // With the TUI over Tor, core gets sockets to purple-cloak and to the launcher's relay
    // thread. The self-test needs neither.
    let route = match (&tor_dirs, &wayland_display) {
        (Some((config, dirs)), Some(_)) => Some(start_route(
            config,
            dirs,
            bin_dir,
            log.as_ref(),
            &mut daemons,
        )?),
        _ => None,
    };

    let mut children = Vec::new();
    let (core_net, net_core) = UnixStream::pair()?;
    let net_strs: Vec<&str> = net_owned.iter().map(String::as_str).collect();
    children.push(spawn(
        &Profile::Net { state_dir, sockets },
        bin_dir,
        sandboxed,
        &net_strs,
        &[(net_core.as_raw_fd(), NET_CORE_FD)],
        background,
    )?);

    children.extend(spawn_core_and_ui(
        wayland_display,
        data_dir,
        bin_dir,
        sandboxed,
        &mode,
        &core_net,
        route.as_ref().map(|r| (&r.core_torctl, &r.core_launcher)),
        log.as_ref(),
    )?);
    // The launcher's copies of the sockets close here, so each child sees EOF when its peer
    // exits.
    drop((core_net, net_core));
    let relay = route.map(|r| r.starter);

    let mut all_ok = true;
    for (name, mut child) in children {
        let status = child.wait()?;
        if !status.success() {
            eprintln!("purple: {name} exited with {status}");
            all_ok = false;
        }
    }
    if let Some(relay) = relay {
        relay.stop();
    }
    daemons.stop()?;
    Ok(all_ok)
}

/// Start kpclientd and wait for its socket; returns the directory purple-subspace mounts.
fn start_kpclientd(
    (binary, config, socket_dir): &KpSetup,
    bin_dir: &Path,
    background: Background<'_>,
    daemons: &mut Daemons,
) -> io::Result<Vec<(PathBuf, &'static str)>> {
    daemons.dirs.push(socket_dir.clone());
    let mut child = spawn_kpclientd(binary, config, socket_dir, bin_dir, background)?;
    let waited = wait_for_socket(&socket_dir.join(KP_SOCKET_NAME), &mut child, SOCKET_WAIT);
    daemons.children.push(child);
    waited?;
    Ok(vec![(socket_dir.clone(), sandbox::KP_SOCKET_DIR)])
}

/// Core's ends of its sockets to purple-cloak and to the relay thread, and the relay.
struct Route {
    core_torctl: UnixStream,
    core_launcher: UnixStream,
    starter: Arc<RelayStarter>,
}

/// Start purple-cloak on tor's control directory, and the thread that starts purple-transporter
/// when core asks.
fn start_route(
    config: &StoreConfig,
    dirs: &TorDirs,
    bin_dir: &Path,
    log: Option<&File>,
    daemons: &mut Daemons,
) -> io::Result<Route> {
    let (core_torctl, torctl_core) = UnixStream::pair()?;
    let mut torctl_args = vec![
        "--control",
        sandbox::TOR_CONTROL,
        "--cookie",
        sandbox::TOR_COOKIE,
    ];
    if config.direct.is_some() {
        torctl_args.push("--direct-available");
    }
    daemons.children.push(spawn(
        &Profile::TorCtl {
            control_dir: dirs.control_dir.clone(),
        },
        bin_dir,
        true,
        &torctl_args,
        &[(torctl_core.as_raw_fd(), TORCTL_CORE_FD)],
        Background(log),
    )?);
    drop(torctl_core);

    let addr = config.direct.map(|(addr, _)| addr.to_string());
    let (relay_dir, bin_dir) = (dirs.relay_dir.clone(), bin_dir.to_path_buf());
    let log = log.map(File::try_clone).transpose()?;
    let spawn_relay: SpawnRelay = Box::new(move || {
        let addr = addr
            .as_deref()
            .ok_or_else(|| io::Error::other("this store has no direct address"))?;
        spawn(
            &Profile::Relay {
                socket_dir: relay_dir.clone(),
            },
            &bin_dir,
            true,
            &["--listen", sandbox::RELAY_SOCKET, "--connect", addr],
            &[],
            Background(log.as_ref()),
        )
    });
    let starter = Arc::new(RelayStarter::new(
        dirs.relay_dir.clone(),
        SOCKET_WAIT,
        spawn_relay,
    ));
    let (core_launcher, launcher_core) = UnixStream::pair()?;
    let served = Arc::clone(&starter);
    thread::spawn(move || serve_relay(launcher_core, &served));
    Ok(Route {
        core_torctl,
        core_launcher,
        starter,
    })
}

type SpawnRelay = Box<dyn Fn() -> io::Result<(String, Child)> + Send + Sync>;

/// Starts purple-transporter when core asks, at most once per run.
struct RelayStarter {
    dir: PathBuf,
    wait: Duration,
    spawn: SpawnRelay,
    child: Mutex<Option<(String, Child)>>,
}

impl RelayStarter {
    fn new(dir: PathBuf, wait: Duration, spawn: SpawnRelay) -> Self {
        Self {
            dir,
            wait,
            spawn,
            child: Mutex::new(None),
        }
    }

    /// Start the relay unless it's running, and wait for its socket.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "holding the lock makes a second start wait for the first"
    )]
    fn start(&self) -> io::Result<()> {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        if child.is_some() {
            return Ok(());
        }
        let mut started = (self.spawn)()?;
        if let Err(err) =
            wait_for_socket(&self.dir.join(RELAY_SOCKET_NAME), &mut started, self.wait)
        {
            started.1.kill().ok();
            started.1.wait().ok();
            return Err(err);
        }
        *child = Some(started);
        Ok(())
    }

    #[cfg(test)]
    fn is_stopped(&self) -> bool {
        self.child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    }

    /// Kill the relay if it runs.
    fn stop(&self) {
        let running = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((_, mut child)) = running {
            child.kill().ok();
            child.wait().ok();
        }
    }
}

/// Answer core's relay requests until it closes the socket.
fn serve_relay(mut core: UnixStream, starter: &RelayStarter) {
    while let Ok(Some(msg)) = LauncherMsg::read_from(&mut core) {
        let reply = match msg {
            LauncherMsg::StartRelay => match starter.start() {
                Ok(()) => LauncherMsg::RelayUp,
                Err(err) => {
                    eprintln!("purple: purple-transporter didn't start: {err}");
                    LauncherMsg::RelayFailed
                }
            },
            LauncherMsg::RelayUp | LauncherMsg::RelayFailed => continue,
        };
        if reply.write_to(&mut core).is_err() {
            return;
        }
    }
}

/// Daemons that don't exit on their own (kpclientd, tor, purple-transporter), and the
/// directories and files made for them.
#[derive(Default)]
struct Daemons {
    children: Vec<(String, Child)>,
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl Daemons {
    /// Kill each daemon (killing its bwrap tears down the whole sandbox) and remove what
    /// was made for it.
    fn stop(self) -> io::Result<()> {
        for (_, mut child) in self.children {
            child.kill().ok();
            child.wait()?;
        }
        for dir in self.dirs {
            fs::remove_dir_all(dir)?;
        }
        for file in self.files {
            fs::remove_file(file)?;
        }
        Ok(())
    }
}

/// Pick where boxes go from the flags. The TUI defaults to the store config.
fn choose_mode(
    dev_provider: Option<String>,
    kpclientd: Option<PathBuf>,
    kp_config: Option<PathBuf>,
    store_config: Option<PathBuf>,
    no_ui: bool,
    sandboxed: bool,
) -> io::Result<Mode> {
    let chosen = [
        dev_provider.is_some(),
        kpclientd.is_some() || kp_config.is_some(),
        store_config.is_some(),
    ];
    if chosen.iter().filter(|&&c| c).count() > 1 {
        return Err(io::Error::other(
            "--dev-provider, --kpclientd and --store-config don't go together",
        ));
    }
    if let Some(addr) = dev_provider {
        return Ok(Mode::Dev(addr));
    }
    if let Some(kp) = prepare_kpclientd(kpclientd, kp_config, sandboxed)? {
        return Ok(Mode::Katzenpost(kp));
    }
    let path = match store_config {
        Some(path) => path,
        None if no_ui => return Ok(Mode::Memory),
        None => xdg_dir("XDG_CONFIG_HOME", ".config")?.join("purple/store.conf"),
    };
    if !sandboxed {
        return Err(io::Error::other(
            "purple won't run tor without bubblewrap around it",
        ));
    }
    let text = match fs::read_to_string(&path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::other(format!(
                "no store configured: put the store's onion address in {} (see the design doc)",
                path.display()
            )));
        }
        other => other?,
    };
    parse_store_config(&text).map(Mode::Tor)
}

/// The directories made for tor: what purple-subspace mounts, tor's control directory (for
/// purple-cloak only), and the empty directory purple-transporter makes its socket in if core
/// asks for it.
struct TorDirs {
    net_sockets: Vec<(PathBuf, &'static str)>,
    control_dir: PathBuf,
    relay_dir: PathBuf,
}

/// Start tor and make the directories purple-subspace, purple-cloak and purple-transporter need.
/// tor bootstraps in the background; purple-cloak watches it. purple-transporter isn't started
/// here.
fn start_tor(
    state_root: &Path,
    bin_dir: &Path,
    background: Background<'_>,
    daemons: &mut Daemons,
) -> io::Result<TorDirs> {
    let parent = private_dir(&runtime_dir()?.join("purple"))?;
    let pid = std::process::id();
    let torrc_path = parent.join(format!("tor-{pid}.rc"));
    let mut torrc_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&torrc_path)?;
    daemons.files.push(torrc_path.clone());
    torrc_file.write_all(torrc::torrc().as_bytes())?;
    let tor_dir = fresh_private_dir(&parent.join(format!("tor-{pid}")))?;
    daemons.dirs.push(tor_dir.clone());
    let control_dir = fresh_private_dir(&parent.join(format!("torctl-{pid}")))?;
    daemons.dirs.push(control_dir.clone());
    let relay_dir = fresh_private_dir(&parent.join(format!("relay-{pid}")))?;
    daemons.dirs.push(relay_dir.clone());
    let profile = Profile::Tor {
        data_dir: private_dir(&state_root.join("tor"))?,
        socket_dir: tor_dir.clone(),
        control_dir: control_dir.clone(),
        torrc: torrc_path,
    };
    let mut tor = spawn_daemon(&profile, bin_dir, &["-f", sandbox::TOR_RC], background)?;
    let waited = wait_for_socket(&tor_dir.join(TOR_SOCKS_NAME), &mut tor, SOCKET_WAIT);
    daemons.children.push(tor);
    waited?;
    Ok(TorDirs {
        net_sockets: vec![
            (tor_dir, sandbox::TOR_SOCKET_DIR),
            (relay_dir.clone(), sandbox::RELAY_SOCKET_DIR),
        ],
        control_dir,
        relay_dir,
    })
}

/// Start `purple-data`, and `purple-lcars` when there's a display. With no display, core runs
/// its self-test. Core is told which store it uses, and pads its polls except over
/// Katzenpost, which sends cover traffic of its own. With `route`, core also gets its
/// sockets to purple-cloak and the relay thread.
#[expect(
    clippy::too_many_arguments,
    reason = "each is one thing core or the UI is started with"
)]
fn spawn_core_and_ui(
    wayland_display: Option<OsString>,
    data_dir: PathBuf,
    bin_dir: &Path,
    sandboxed: bool,
    mode: &Mode,
    core_net: &UnixStream,
    route: Option<(&UnixStream, &UnixStream)>,
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
            let mut core_fds = vec![
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
            let mut core_args = vec!["--data-dir", data_arg.as_str()];
            let store = core_store_arg(mode);
            if let Some(store) = &store {
                core_args.extend(["--store", store.as_str()]);
            }
            if matches!(mode, Mode::Katzenpost(_)) {
                core_args.push("--no-read-padding");
            }
            if let Some((torctl, launcher)) = route {
                core_args.push("--torctl");
                core_fds.push((torctl.as_raw_fd(), CORE_TORCTL_FD));
                core_fds.push((launcher.as_raw_fd(), CORE_LAUNCHER_FD));
            }
            out.push(spawn(
                &Profile::Core { data_dir },
                bin_dir,
                sandboxed,
                &core_args,
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
    // One directory per run: purple instances with different profiles share the runtime
    // directory, and each must reach only its own daemon.
    let parent = private_dir(&runtime_dir()?.join("purple"))?;
    let socket_dir = fresh_private_dir(&parent.join(format!("kp-{}", std::process::id())))?;
    Ok(Some((binary, config, socket_dir)))
}

/// Create `dir` empty and readable only by the user. Whatever was there (left by a crashed
/// run with the same pid) is removed first.
fn fresh_private_dir(dir: &Path) -> io::Result<PathBuf> {
    match fs::remove_dir_all(dir) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        Ok(()) | Err(_) => {}
    }
    DirBuilder::new().mode(0o700).create(dir)?;
    Ok(dir.to_path_buf())
}

/// Wait up to `wait` until a daemon has made its socket, so `purple-subspace` can connect at
/// once.
fn wait_for_socket(
    path: &Path,
    (name, daemon): &mut (String, Child),
    wait: Duration,
) -> io::Result<()> {
    let start = Instant::now();
    while !path.exists() {
        if let Some(status) = daemon.try_wait()? {
            return Err(io::Error::other(format!("{name} exited with {status}")));
        }
        if start.elapsed() >= wait {
            return Err(io::Error::other(format!(
                "{name} didn't open its socket in time"
            )));
        }
        thread::sleep(SOCKET_POLL);
    }
    Ok(())
}

/// What core's `--store` says: which store its invites name. The self-test's in-memory
/// network passes nothing.
fn core_store_arg(mode: &Mode) -> Option<String> {
    match mode {
        Mode::Memory => None,
        Mode::Dev(_) => Some("dev".to_owned()),
        Mode::Katzenpost(_) => Some("namenlos".to_owned()),
        Mode::Tor(config) => Some(format!("tor:{}", config.onion)),
    }
}

/// `purple-subspace`'s Tor flags, with tor's SOCKS socket and purple-transporter's where its sandbox
/// mounts them. Two packets a second unless told otherwise.
fn tor_net_args(config: &StoreConfig, send_interval_ms: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = ["--tor", sandbox::TOR_SOCKS, "--onion"]
        .map(str::to_owned)
        .into();
    args.push(format!("{}:{}", config.onion, config.port));
    if let Some((_, key)) = config.direct {
        args.extend([
            "--direct-relay".to_owned(),
            sandbox::RELAY_SOCKET.to_owned(),
            "--direct-key".to_owned(),
            hex(&key),
        ]);
    }
    args.extend([
        "--send-interval-ms".to_owned(),
        send_interval_ms.unwrap_or(TOR_SEND_INTERVAL_MS).to_owned(),
    ]);
    args
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        // Writing to a String can't fail.
        write!(out, "{b:02x}").ok();
        out
    })
}

/// Arguments for `purple-subspace`.
fn net_args(mode: &Mode, send_interval_ms: Option<&str>, no_ui: bool) -> Vec<String> {
    let mut args = Vec::new();
    match mode {
        Mode::Tor(config) => {
            // Tor carries a few requests a second per circuit, so the self-test runs at the
            // TUI's rate too.
            return tor_net_args(config, send_interval_ms);
        }
        Mode::Dev(addr) => args.extend(["--dev-provider".to_owned(), addr.clone()]),
        Mode::Katzenpost(_) => {
            args.extend(["--katzenpost".to_owned(), sandbox::KP_SOCKET.to_owned()]);
        }
        Mode::Memory => {}
    }
    let send_interval = match (send_interval_ms, no_ui) {
        (Some(ms), _) => Some(ms),
        (None, true) => Some(SELF_TEST_SEND_INTERVAL_MS),
        (None, false) => None,
    };
    if let Some(ms) = send_interval {
        args.extend(["--send-interval-ms".to_owned(), ms.to_owned()]);
    }
    args
}

/// Run Katzenpost's client daemon sandboxed.
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
    spawn_daemon(&profile, bin_dir, &["-c", sandbox::KP_CONFIG], background)
}

/// Run a daemon purple can't modify (kpclientd, tor) under bwrap, with purple's seccomp
/// filters installed by bwrap from pipes.
fn spawn_daemon(
    profile: &Profile,
    bin_dir: &Path,
    args: &[&str],
    background: Background<'_>,
) -> io::Result<(String, Child)> {
    let mut cmd = sandbox::command(profile, bin_dir, true, args);
    let mut readers = Vec::new();
    for program in seccomp_programs(Network::Allowed)? {
        let (reader, mut writer) = io::pipe()?;
        writer.write_all(&program)?;
        readers.push(reader);
    }
    let fds: Vec<(RawFd, RawFd)> = readers
        .iter()
        .map(AsRawFd::as_raw_fd)
        .zip(sandbox::DAEMON_SECCOMP_FDS)
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

/// Refuse a `kpclientd` config that wouldn't listen where `purple-subspace` connects, or that
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

/// `purple-lcars` inherits the terminal.
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
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn fresh_private_dir_starts_empty_and_private() {
        let dir = std::env::temp_dir().join(format!("purple-fresh-{}", std::process::id()));
        fresh_private_dir(&dir).unwrap();
        fs::write(dir.join(KP_SOCKET_NAME), b"stale").unwrap();
        fresh_private_dir(&dir).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&dir).unwrap().permissions());
        assert_eq!(mode & 0o777, 0o700);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tor_mode_args() {
        let config = StoreConfig {
            onion: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion".into(),
            port: 80,
            direct: Some(("192.0.2.10:4443".parse().unwrap(), [0x0f; 32])),
        };
        let args = tor_net_args(&config, None);
        let joined = args.join(" ");
        assert!(joined.contains("--tor /run/tor/socks.sock"));
        assert!(!joined.contains("--tor-control") && !joined.contains("--tor-cookie"));
        assert!(
            joined.contains(
                "--onion abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion:80"
            )
        );
        assert!(joined.contains("--direct-relay /run/relay/relay.sock"));
        assert!(joined.contains(&format!("--direct-key {}", "0f".repeat(32))));
        assert!(
            joined.contains("--send-interval-ms 500"),
            "2 packets a second"
        );
        assert_eq!(
            core_store_arg(&Mode::Tor(config.clone())),
            Some(format!("tor:{}", config.onion))
        );
        let self_test = net_args(&Mode::Tor(config), None, true).join(" ");
        assert!(
            self_test.contains("--send-interval-ms 500"),
            "the self-test can't go faster than Tor"
        );
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

    #[test]
    fn no_relay_until_asked_and_only_once() {
        let dir =
            std::env::temp_dir().join(format!("purple-transporter-start-{}", std::process::id()));
        fresh_private_dir(&dir).unwrap();
        let spawned = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&spawned);
        let socket = dir.join(RELAY_SOCKET_NAME);
        let starter = RelayStarter::new(
            dir.clone(),
            Duration::from_secs(5),
            Box::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                fs::write(&socket, b"")?;
                Ok((
                    "purple-transporter".to_owned(),
                    Command::new("sleep").arg("30").spawn()?,
                ))
            }),
        );
        assert_eq!(spawned.load(Ordering::SeqCst), 0, "nothing at launch");
        starter.start().unwrap();
        starter.start().unwrap();
        assert_eq!(spawned.load(Ordering::SeqCst), 1);
        starter.stop();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_relay_without_a_socket_fails_and_is_stopped() {
        let dir =
            std::env::temp_dir().join(format!("purple-transporter-fail-{}", std::process::id()));
        fresh_private_dir(&dir).unwrap();
        let starter = RelayStarter::new(
            dir.clone(),
            Duration::from_millis(200),
            Box::new(|| {
                Ok((
                    "purple-transporter".to_owned(),
                    Command::new("sleep").arg("30").spawn()?,
                ))
            }),
        );
        assert!(starter.start().is_err());
        assert!(starter.is_stopped());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_relay_socket_speaks_launcher_messages() {
        let dir =
            std::env::temp_dir().join(format!("purple-transporter-ipc-{}", std::process::id()));
        fresh_private_dir(&dir).unwrap();
        let socket = dir.join(RELAY_SOCKET_NAME);
        let starter = RelayStarter::new(
            dir.clone(),
            Duration::from_secs(5),
            Box::new(move || {
                fs::write(&socket, b"")?;
                Ok((
                    "purple-transporter".to_owned(),
                    Command::new("sleep").arg("30").spawn()?,
                ))
            }),
        );
        let (mut core, launcher) = UnixStream::pair().unwrap();
        thread::scope(|s| {
            let starter = &starter;
            s.spawn(move || serve_relay(launcher, starter));
            LauncherMsg::StartRelay.write_to(&mut core).unwrap();
            assert_eq!(
                LauncherMsg::read_from(&mut core).unwrap(),
                Some(LauncherMsg::RelayUp)
            );
            drop(core);
        });
        starter.stop();
        fs::remove_dir_all(&dir).unwrap();
    }
}
