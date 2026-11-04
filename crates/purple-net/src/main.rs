//! purple-net: relays packets between `purple-core` and the mixnet.

use std::io;
use std::process::ExitCode;

use purple_ipc::{NET_CORE_FD, NetMsg, inherited_stream};
use purple_net::{FakeTransport, Transport};

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
    // SAFETY: the launcher hands this fd to purple-net and nothing else here uses it.
    let mut core = unsafe { inherited_stream(NET_CORE_FD)? };
    // Swapped for the Nym client in build step 3.
    let mut transport = FakeTransport::default();

    while let Some(msg) = NetMsg::read_from(&mut core)? {
        match msg {
            NetMsg::Send { mailbox, packet } => transport.send(&mailbox, packet)?,
            NetMsg::Fetch { mailbox } => {
                for packet in transport.fetch(&mailbox)? {
                    NetMsg::Delivered { mailbox, packet }.write_to(&mut core)?;
                }
                NetMsg::FetchDone { mailbox }.write_to(&mut core)?;
            }
            NetMsg::Delivered { .. } | NetMsg::FetchDone { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "purple-core sent a message only purple-net may send",
                ));
            }
        }
    }
    Ok(())
}
