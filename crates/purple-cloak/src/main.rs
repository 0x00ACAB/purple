//! purple-cloak: drives tor's control port for purple. It reads core's messages on fd 3
//! and answers there; it has no network, can't write anywhere, and sees only tor's control
//! directory.
//!
//! Usage: `purple-cloak --control <socket> --cookie <file> [--direct-available]`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use purple_cloak::bridges;
use purple_cloak::driver::{Setup, drive};
use purple_cloak::fallback::STALL;
use purple_combadge::torctl::TorCtlMsg;
use purple_combadge::{TORCTL_CORE_FD, inherited_stream};
use purple_shields::sandbox::{Network, Policy, restrict};

const USAGE: &str = "usage: purple-cloak --control <socket> --cookie <file> [--direct-available]";
/// How often tor's bootstrap progress is checked.
const EVERY: Duration = Duration::from_secs(1);

#[derive(Debug)]
struct Options {
    control: PathBuf,
    cookie: PathBuf,
    direct_available: bool,
}

fn parse(args: &[&str]) -> io::Result<Options> {
    let (mut control, mut cookie, mut direct_available) = (None, None, false);
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        match arg {
            "--control" => control = args.next().map(PathBuf::from),
            "--cookie" => cookie = args.next().map(PathBuf::from),
            "--direct-available" => direct_available = true,
            _ => return Err(io::Error::other(USAGE)),
        }
    }
    Ok(Options {
        control: control.ok_or_else(|| io::Error::other(USAGE))?,
        cookie: cookie.ok_or_else(|| io::Error::other(USAGE))?,
        direct_available,
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-cloak: {err}");
            ExitCode::FAILURE
        }
    }
}

#[expect(unsafe_code, reason = "adopting the socket the launcher passed in")]
fn run() -> io::Result<()> {
    purple_shields::harden()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = parse(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    // Before restrict, while the plugin binaries can still be looked for.
    let builtin = bridges::available();
    let control_dir = options.control.parent().unwrap_or_else(|| Path::new("/"));
    // Landlock grants it as writable; bwrap mounts it read-only.
    restrict(&Policy {
        writable: &[control_dir],
        network: Network::Local,
    })?;
    // SAFETY: the launcher hands this fd to purple-cloak and nothing else here uses it.
    let core = unsafe { inherited_stream(TORCTL_CORE_FD)? };
    let (tx, from_core) = mpsc::channel();
    let mut core_in = core.try_clone()?;
    thread::spawn(move || {
        while let Ok(Some(msg)) = TorCtlMsg::read_from(&mut core_in) {
            if tx.send(msg).is_err() {
                return;
            }
        }
    });
    let setup = Setup {
        control: options.control,
        cookie: options.cookie,
        direct_available: options.direct_available,
        bridges: builtin,
        stall: STALL,
    };
    let mut to_core = core;
    drive(&setup, &from_core, &mut to_core, EVERY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options() {
        let o = parse(&[
            "--control",
            "/run/torctl/control.sock",
            "--cookie",
            "/run/torctl/control.cookie",
            "--direct-available",
        ])
        .unwrap();
        assert!(o.direct_available);
        assert!(
            !parse(&["--control", "/c", "--cookie", "/k"])
                .unwrap()
                .direct_available
        );
        assert!(parse(&["--control", "/c"]).is_err());
        assert!(parse(&["--cookie", "/k", "--control", "/c", "--bogus"]).is_err());
    }
}
