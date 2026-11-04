//! purple-net: relays packets between `purple-core` and the network.
//!
//! With `--dev-provider <addr>` it forwards to a local `purple-devprovider`, so several
//! purple instances on one machine can talk. Without it, it uses an in-memory network that
//! only this instance can see.

use std::io;
use std::process::ExitCode;

use landlock::RulesetStatus;
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_ipc::{NET_CORE_FD, inherited_stream};
use purple_net::{DevProviderTransport, FakeTransport, serve};

const NAME: &str = "purple-net";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-net: {err}");
            ExitCode::FAILURE
        }
    }
}

#[expect(unsafe_code, reason = "adopting the socket the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    note_sandbox(&restrict(&Policy {
        writable: &[],
        network: Network::Allowed,
    })?);
    let dev_provider = dev_provider_arg()?;
    // SAFETY: the launcher hands this fd to purple-net and nothing else here uses it.
    let mut core = unsafe { inherited_stream(NET_CORE_FD)? };
    // The mixnet transport replaces these once the Nym/Katzenpost choice is made.
    match dev_provider {
        Some(addr) => serve(&mut core, &mut DevProviderTransport::connect(&addr)?),
        None => serve(&mut core, &mut FakeTransport::default()),
    }
}

fn dev_provider_arg() -> io::Result<Option<String>> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (None, _, _) => Ok(None),
        (Some("--dev-provider"), Some(addr), None) => Ok(Some(addr)),
        _ => Err(io::Error::other(
            "usage: purple-net [--dev-provider <addr>]",
        )),
    }
}

/// Log how much of the sandbox the kernel enforced, if not all of it.
fn note_sandbox(report: &Report) {
    if report.landlock != RulesetStatus::FullyEnforced {
        eprintln!(
            "{NAME}: warning: Landlock only {:?} on this kernel",
            report.landlock
        );
    }
}
