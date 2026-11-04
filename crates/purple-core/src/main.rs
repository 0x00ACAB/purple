//! purple-core: holds keys and message state. No network access, no display.

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use purple_core::fragment::{Reassembler, split};
use purple_core::invite::Invite;
use purple_core::session::Account;
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

/// Two local accounts connect through an invite and exchange messages, with every message
/// fragmented and carried through purple-net.
fn self_test(net: &mut UnixStream) -> io::Result<()> {
    let bundle_box = MailboxId([0xB1; MAILBOX_ID_LEN]);
    let to_bob = MailboxId([0xB0; MAILBOX_ID_LEN]);
    // Until message contents carry it, Alice's reply mailbox is fixed here.
    let to_alice = MailboxId([0xA1; MAILBOX_ID_LEN]);
    let mut alice = Account::generate().map_err(io::Error::other)?;
    let mut bob = Account::generate().map_err(io::Error::other)?;

    // Bob shows a QR code and stores his sealed bundle at the provider.
    let (invite, sealed) = bob
        .create_invite(bundle_box, to_bob)
        .map_err(io::Error::other)?;
    send(net, bundle_box, &sealed)?;
    let qr = invite.encode();

    // Alice scans it, fetches the bundle and starts the session.
    let scanned = Invite::decode(&qr).map_err(io::Error::other)?;
    let fetched = receive(net, scanned.bundle_mailbox())?;
    let first = alice
        .accept_invite("bob", &scanned, &fetched)
        .map_err(io::Error::other)?;
    expect(first == to_bob)?;

    let hello = alice
        .encrypt("bob", b"hello bob")
        .map_err(io::Error::other)?;
    send(net, to_bob, &hello)?;
    let at_bob = receive(net, to_bob)?;
    expect(bob.decrypt("alice", &at_bob).map_err(io::Error::other)? == b"hello bob")?;

    let reply = bob
        .encrypt("alice", b"hello alice")
        .map_err(io::Error::other)?;
    send(net, to_alice, &reply)?;
    let at_alice = receive(net, to_alice)?;
    expect(alice.decrypt("bob", &at_alice).map_err(io::Error::other)? == b"hello alice")?;

    eprintln!("purple-core: self-test ok (invite, PQXDH handshake and reply through purple-net)");
    Ok(())
}

fn send(net: &mut UnixStream, mailbox: MailboxId, message: &[u8]) -> io::Result<()> {
    for packet in split(message)? {
        NetMsg::Send { mailbox, packet }.write_to(net)?;
    }
    Ok(())
}

/// Fetch `mailbox` and return the one message it should hold.
fn receive(net: &mut UnixStream, mailbox: MailboxId) -> io::Result<Vec<u8>> {
    NetMsg::Fetch { mailbox }.write_to(net)?;
    let mut reassembler = Reassembler::default();
    let mut messages = Vec::new();
    loop {
        match NetMsg::read_from(net)? {
            Some(NetMsg::Delivered {
                mailbox: from,
                packet,
            }) if from == mailbox => {
                messages.extend(reassembler.push(&packet)?);
            }
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
    match <[Vec<u8>; 1]>::try_from(messages) {
        Ok([message]) => Ok(message),
        Err(_) => Err(io::Error::other(
            "expected exactly one message in the mailbox",
        )),
    }
}

fn expect(ok: bool) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(
            "self-test message did not come back intact",
        ))
    }
}
