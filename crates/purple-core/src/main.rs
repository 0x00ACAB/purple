//! purple-core: holds keys and message state. No network access, no display.

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use purple_core::invite::Invite;
use purple_core::messenger::{Event, Messenger, Outgoing};
use purple_ipc::{CORE_NET_FD, CORE_UI_FD, NetMsg, inherited_stream};

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

/// Two local messengers connect through an invite and exchange messages. Every packet is
/// sealed for its queue and carried through purple-net.
fn self_test(net: &mut UnixStream) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    let mut alice = Messenger::new().map_err(io::Error::other)?;
    let mut bob = Messenger::new().map_err(io::Error::other)?;

    // Bob shows a QR code and stores his bundle; Alice scans it.
    let (invite, bundle) = bob.create_invite("alice").map_err(io::Error::other)?;
    deliver(net, bundle)?;
    let scanned = Invite::decode(&invite.encode()).map_err(io::Error::other)?;
    alice
        .accept_invite("bob", scanned)
        .map_err(io::Error::other)?;

    expect(poll(net, &mut alice, now)? == [Event::Connected("bob".into())])?;
    expect(poll(net, &mut bob, now)? == [Event::Connected("alice".into())])?;

    deliver(
        net,
        bob.send("alice", b"hello alice", now)
            .map_err(io::Error::other)?,
    )?;
    expect(poll(net, &mut alice, now)? == [text("bob", b"hello alice")])?;
    deliver(
        net,
        alice
            .send("bob", b"hello bob", now)
            .map_err(io::Error::other)?,
    )?;
    expect(poll(net, &mut bob, now)? == [text("alice", b"hello bob")])?;

    eprintln!("purple-core: self-test ok (invite, hello, messages both ways through purple-net)");
    Ok(())
}

fn deliver(net: &mut UnixStream, out: Outgoing) -> io::Result<()> {
    let mailbox = out.mailbox;
    for packet in out.packets {
        NetMsg::Send { mailbox, packet }.write_to(net)?;
    }
    Ok(())
}

/// Fetch every mailbox `messenger` polls, hand it the packets, and deliver what it sends.
fn poll(net: &mut UnixStream, messenger: &mut Messenger, now: u64) -> io::Result<Vec<Event>> {
    let mut events = Vec::new();
    for mailbox in messenger.mailboxes(now).map_err(io::Error::other)? {
        NetMsg::Fetch { mailbox }.write_to(net)?;
        let mut packets = Vec::new();
        loop {
            match NetMsg::read_from(net)? {
                Some(NetMsg::Delivered {
                    mailbox: from,
                    packet,
                }) if from == mailbox => {
                    packets.push(packet);
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
        for packet in packets {
            let step = messenger
                .receive(mailbox, &packet, now)
                .map_err(io::Error::other)?;
            events.extend(step.events);
            for out in step.outgoing {
                deliver(net, out)?;
            }
        }
    }
    Ok(events)
}

fn text(from: &str, body: &[u8]) -> Event {
    Event::Message {
        from: from.into(),
        body: body.to_vec(),
    }
}

fn expect(ok: bool) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(
            "self-test did not see the expected events",
        ))
    }
}
