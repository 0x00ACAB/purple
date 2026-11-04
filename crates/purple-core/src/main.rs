//! purple-core: holds keys and message state. No network access, no display.

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use purple_core::{pad, unpad};
use purple_ipc::{CORE_NET_FD, CORE_UI_FD, MAILBOX_ID_LEN, MailboxId, NetMsg, inherited_stream};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-core: {err}");
            ExitCode::FAILURE
        }
    }
}

#[expect(unsafe_code, reason = "adopting the sockets the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    let with_ui = !std::env::args().any(|arg| arg == "--no-ui");

    // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
    let mut net = unsafe { inherited_stream(CORE_NET_FD)? };
    self_test(&mut net)?;

    if with_ui {
        // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
        let mut ui = unsafe { inherited_stream(CORE_UI_FD)? };
        // No UI protocol yet: wait for the UI to close its end.
        io::copy(&mut ui, &mut io::sink())?;
    }
    Ok(())
}

/// Send one packet to a mailbox through purple-net and fetch it back.
fn self_test(net: &mut UnixStream) -> io::Result<()> {
    let mailbox = MailboxId([0x42; MAILBOX_ID_LEN]);
    let message = b"purple-core self-test";
    NetMsg::Send {
        mailbox,
        packet: pad(message)?,
    }
    .write_to(net)?;
    NetMsg::Fetch { mailbox }.write_to(net)?;

    let mut received = Vec::new();
    loop {
        match NetMsg::read_from(net)? {
            Some(NetMsg::Delivered {
                mailbox: from,
                packet,
            }) if from == mailbox => received.push(packet),
            Some(NetMsg::FetchDone { mailbox: from }) if from == mailbox => break,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected reply from purple-net",
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "purple-net closed the socket",
                ));
            }
        }
    }

    match received.as_slice() {
        [packet] if unpad(packet)? == message => {
            eprintln!("purple-core: round trip through purple-net ok");
            Ok(())
        }
        _ => Err(io::Error::other(
            "self-test packet did not come back intact",
        )),
    }
}
