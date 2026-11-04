//! purple-core: holds keys and message state. No network access, no display.
//!
//! Normally it serves `purple-ui`: commands come in on one thread, and the main loop
//! handles them and polls the network every [`POLL_INTERVAL`]. With `--no-ui` it runs a
//! self-test through `purple-net` and exits.

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use purple_core::invite::Invite;
use purple_core::messenger::{Event, Messenger, Outgoing};
use purple_core::session;
use purple_ipc::ui::{MAX_BODY_LEN, MAX_ERROR_LEN, UiCmd, UiEvent};
use purple_ipc::{CORE_NET_FD, CORE_UI_FD, MailboxId, NetMsg, Packet, inherited_stream};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

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
    let no_ui = std::env::args().any(|arg| arg == "--no-ui");

    // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
    let mut net = unsafe { inherited_stream(CORE_NET_FD)? };
    if no_ui {
        return self_test(&mut net);
    }
    // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
    let ui = unsafe { inherited_stream(CORE_UI_FD)? };
    serve_ui(&mut net, ui)
}

/// Handle UI commands and poll the network until the UI closes its socket.
fn serve_ui(net: &mut UnixStream, mut ui: UnixStream) -> io::Result<()> {
    let mut messenger = Messenger::new().map_err(io::Error::other)?;
    let commands = spawn_command_reader(ui.try_clone()?);

    loop {
        match commands.recv_timeout(POLL_INTERVAL) {
            Ok(Ok(cmd)) => {
                if let Err(err) = handle(cmd, &mut messenger, net, &mut ui) {
                    report(&mut ui, &err.to_string())?;
                }
            }
            Ok(Err(err)) => return Err(err),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        let (events, errors) = poll(net, &mut messenger, now()?)?;
        for event in events {
            to_ui_event(event).write_to(&mut ui)?;
        }
        for err in errors {
            report(&mut ui, &format!("dropped a packet: {err}"))?;
        }
    }
}

/// Read UI commands on their own thread so the main loop can poll on a timer. The channel
/// closes when the UI closes its socket.
fn spawn_command_reader(mut ui: UnixStream) -> mpsc::Receiver<io::Result<UiCmd>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match UiCmd::read_from(&mut ui) {
                Ok(Some(cmd)) => {
                    if tx.send(Ok(cmd)).is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(err) => {
                    // The main loop stops on this error, so a failed send changes nothing.
                    tx.send(Err(err)).ok();
                    return;
                }
            }
        }
    });
    rx
}

fn handle(
    cmd: UiCmd,
    messenger: &mut Messenger,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> session::Result<()> {
    match cmd {
        UiCmd::CreateInvite { contact } => {
            let (invite, bundle) = messenger.create_invite(&contact)?;
            deliver(net, bundle)?;
            UiEvent::InviteCreated {
                contact,
                invite: invite.to_text().to_string(),
            }
            .write_to(ui)?;
        }
        UiCmd::AcceptInvite { contact, invite } => {
            messenger.accept_invite(&contact, Invite::from_text(&invite)?)?;
        }
        UiCmd::Send { contact, body } => {
            deliver(net, messenger.send(&contact, body.as_bytes(), now()?)?)?;
        }
    }
    Ok(())
}

fn to_ui_event(event: Event) -> UiEvent {
    match event {
        Event::Connected(contact) => UiEvent::Connected { contact },
        Event::Message { from, body } => UiEvent::Message {
            from,
            body: clip(&String::from_utf8_lossy(&body), MAX_BODY_LEN),
        },
    }
}

fn report(ui: &mut UnixStream, message: &str) -> io::Result<()> {
    UiEvent::Error {
        message: clip(message, MAX_ERROR_LEN),
    }
    .write_to(ui)
}

/// The longest prefix of `text` that fits in `max` bytes without splitting a character.
fn clip(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default().to_owned()
}

/// Two local messengers connect through an invite and exchange messages. Every packet is
/// sealed for its queue and carried through purple-net.
fn self_test(net: &mut UnixStream) -> io::Result<()> {
    let now = now()?;
    let mut alice = Messenger::new().map_err(io::Error::other)?;
    let mut bob = Messenger::new().map_err(io::Error::other)?;

    // Bob creates an invite and stores his bundle; Alice pastes the invite text.
    let (invite, bundle) = bob.create_invite("alice").map_err(io::Error::other)?;
    deliver(net, bundle).map_err(io::Error::other)?;
    let pasted = Invite::from_text(&invite.to_text()).map_err(io::Error::other)?;
    alice
        .accept_invite("bob", pasted)
        .map_err(io::Error::other)?;

    expect(poll_strict(net, &mut alice, now)? == [Event::Connected("bob".into())])?;
    expect(poll_strict(net, &mut bob, now)? == [Event::Connected("alice".into())])?;

    let to_alice = bob
        .send("alice", b"hello alice", now)
        .map_err(io::Error::other)?;
    deliver(net, to_alice).map_err(io::Error::other)?;
    expect(poll_strict(net, &mut alice, now)? == [text("bob", b"hello alice")])?;
    let to_bob = alice
        .send("bob", b"hello bob", now)
        .map_err(io::Error::other)?;
    deliver(net, to_bob).map_err(io::Error::other)?;
    expect(poll_strict(net, &mut bob, now)? == [text("alice", b"hello bob")])?;

    eprintln!("purple-core: self-test ok (invite, hello, messages both ways through purple-net)");
    Ok(())
}

fn deliver(net: &mut UnixStream, out: Outgoing) -> session::Result<()> {
    let mailbox = out.mailbox;
    for packet in out.packets {
        NetMsg::Send { mailbox, packet }.write_to(net)?;
    }
    Ok(())
}

/// Fetch every mailbox `messenger` polls, hand it the packets, and deliver what it sends.
/// Packets the messenger rejects are skipped and their errors returned; I/O errors with
/// purple-net are fatal.
fn poll(
    net: &mut UnixStream,
    messenger: &mut Messenger,
    now: u64,
) -> io::Result<(Vec<Event>, Vec<session::Error>)> {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for mailbox in messenger.mailboxes(now).map_err(io::Error::other)? {
        for packet in fetch(net, mailbox)? {
            match messenger.receive(mailbox, &packet, now) {
                Ok(step) => {
                    events.extend(step.events);
                    for out in step.outgoing {
                        deliver(net, out).map_err(io::Error::other)?;
                    }
                }
                Err(err) => errors.push(err),
            }
        }
    }
    Ok((events, errors))
}

/// [`poll`], treating any rejected packet as a failure.
fn poll_strict(
    net: &mut UnixStream,
    messenger: &mut Messenger,
    now: u64,
) -> io::Result<Vec<Event>> {
    let (events, errors) = poll(net, messenger, now)?;
    errors
        .into_iter()
        .next()
        .map_or(Ok(events), |err| Err(io::Error::other(err)))
}

fn fetch(net: &mut UnixStream, mailbox: MailboxId) -> io::Result<Vec<Packet>> {
    NetMsg::Fetch { mailbox }.write_to(net)?;
    let mut packets = Vec::new();
    loop {
        match NetMsg::read_from(net)? {
            Some(NetMsg::Delivered {
                mailbox: from,
                packet,
            }) if from == mailbox => packets.push(packet),
            Some(NetMsg::FetchDone { mailbox: from }) if from == mailbox => return Ok(packets),
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
}

fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
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
