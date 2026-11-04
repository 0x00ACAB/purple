//! purple-devprovider: a local stand-in for the mixnet and its providers, so several purple
//! instances on one machine can reach each other during development.
//!
//! It keeps every mailbox in memory and sees which instance uses which mailbox, so it
//! offers none of the mixnet's privacy. Never expose it beyond loopback.

use std::io;
use std::net::TcpListener;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use landlock::RulesetStatus;
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_net::{FakeTransport, serve};

const NAME: &str = "purple-devprovider";

const DEFAULT_ADDR: &str = "127.0.0.1:7878";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-devprovider: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<()> {
    purple_harden::harden()?;
    note_sandbox(&restrict(&Policy {
        writable: &[],
        network: Network::Allowed,
    })?);
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDR.to_owned());
    let listener = TcpListener::bind(&addr)?;
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(io::Error::other("refusing to listen beyond loopback"));
    }
    eprintln!(
        "purple-devprovider: listening on {}",
        listener.local_addr()?
    );

    // Cover traffic goes to mailboxes nobody fetches; drop it after an hour.
    let network = FakeTransport::with_retention(Duration::from_hours(1));
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut transport = network.clone();
        thread::spawn(move || {
            if let Err(err) = serve(&mut stream, &mut transport) {
                eprintln!("purple-devprovider: client error: {err}");
            }
        });
    }
    Ok(())
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
