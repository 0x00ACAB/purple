//! purple-core: holds keys and message state. No network access, no display.
//!
//! Normally it serves `purple-ui`: it asks for the passphrase, unlocks (or creates) the
//! vault in `--data-dir`, replays contacts and history, then handles commands and polls the
//! network every [`POLL_INTERVAL`]. With `--no-ui` it runs an in-memory self-test through
//! `purple-net` and exits.
//!
//! Every step that changes state saves the vault before any packet it produced is sent.
//! Otherwise a crash after sending but before saving would restart from an older ratchet
//! state and could reuse a message key.

use std::collections::HashSet;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use landlock::RulesetStatus;
use purple_core::invite::Invite;
use purple_core::messenger::{Event, Messenger, Outgoing};
use purple_core::session;
use purple_core::vault::{HistoryEntry, KdfParams, Vault};
use purple_harden::sandbox::{Network, Policy, Report, restrict};
use purple_ipc::ui::{MAX_BODY_LEN, MAX_ERROR_LEN, UiCmd, UiEvent};
use purple_ipc::{
    BoxRef, CORE_NET_FD, CORE_UI_FD, NetMsg, Packet, SEED_LEN, StreamSeed, inherited_stream,
};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use zeroize::Zeroizing;

const NAME: &str = "purple-core";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Reads in a poll's first wave come in multiples of this.
const POLL_ROUND: usize = 16;
/// Most box reads one poll makes, so a long backlog can't stall the loop.
const MAX_READS_PER_POLL: usize = 256;
const SELF_TEST_POLLS: u32 = 200;
const SELF_TEST_WAIT: Duration = Duration::from_millis(100);
const USAGE: &str = "usage: purple-core (--no-ui | --data-dir <dir>)";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-core: {err}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    SelfTest,
    Serve(PathBuf),
}

fn parse_args() -> io::Result<Mode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--no-ui"] => Ok(Mode::SelfTest),
        ["--data-dir", dir] => Ok(Mode::Serve(PathBuf::from(dir))),
        _ => Err(io::Error::other(USAGE)),
    }
}

#[expect(unsafe_code, reason = "adopting the sockets the launcher passed in")]
fn run() -> io::Result<()> {
    purple_harden::harden()?;
    let mode = parse_args()?;
    let writable: Vec<&Path> = match &mode {
        Mode::SelfTest => Vec::new(),
        Mode::Serve(data_dir) => vec![data_dir.as_path()],
    };
    note_sandbox(&restrict(&Policy {
        writable: &writable,
        network: Network::Denied,
    })?);

    // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
    let mut net = unsafe { inherited_stream(CORE_NET_FD)? };
    match mode {
        Mode::SelfTest => self_test(&mut net),
        Mode::Serve(data_dir) => {
            // SAFETY: the launcher hands this fd to purple-core and nothing else here uses it.
            let ui = unsafe { inherited_stream(CORE_UI_FD)? };
            serve_ui(&mut net, ui, &data_dir)
        }
    }
}

/// What one step produced, applied by [`commit`] in a safe order.
#[derive(Default)]
struct Effects {
    outgoing: Vec<Outgoing>,
    history: Vec<HistoryEntry>,
    events: Vec<UiEvent>,
    /// Whether messenger state may have changed (a ratchet moved, a key was used).
    changed: bool,
}

/// Unlock the vault, replay what it holds, then serve the UI until it closes its socket.
fn serve_ui(net: &mut UnixStream, mut ui: UnixStream, data_dir: &Path) -> io::Result<()> {
    let commands = spawn_command_reader(ui.try_clone()?);
    let Some((mut messenger, mut vault)) = unlock(&commands, &mut ui, data_dir)? else {
        return Ok(());
    };
    eprintln!(
        "purple-core: unlocked; master key protection: {:?}",
        vault.protection()
    );
    replay(&messenger, &vault, &mut ui)?;

    // Polls run on a fixed clock, never in response to what the user does, so their
    // timing says nothing about activity.
    let mut next_poll = Instant::now();
    loop {
        let wait = next_poll.saturating_duration_since(Instant::now());
        match commands.recv_timeout(wait) {
            Ok(Ok(UiCmd::ChangePassphrase { old, new })) => {
                let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
                let changed = messenger.to_snapshot().and_then(|snapshot| {
                    vault.change_passphrase(&old, &new, KdfParams::DEFAULT, &snapshot)
                });
                match changed {
                    Ok(()) => UiEvent::PassphraseChanged.write_to(&mut ui)?,
                    Err(err) => report(&mut ui, &err.to_string())?,
                }
            }
            Ok(Ok(cmd)) => match handle(cmd, &mut messenger) {
                Ok(effects) => commit(effects, &messenger, &mut vault, net, &mut ui)?,
                Err(err) => report(&mut ui, &err.to_string())?,
            },
            Ok(Err(err)) => return Err(err),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if Instant::now() >= next_poll {
            let (effects, errors) = poll(net, &mut messenger, now()?)?;
            commit(effects, &messenger, &mut vault, net, &mut ui)?;
            for err in errors {
                report(&mut ui, &format!("dropped a packet: {err}"))?;
            }
            next_poll = next_on_grid(next_poll);
        }
    }
}

/// The next poll time on the fixed grid. If polling fell behind, skip the missed slots
/// rather than polling in a burst.
fn next_on_grid(previous: Instant) -> Instant {
    let now = Instant::now();
    let mut next = previous;
    while next <= now {
        next = next.checked_add(POLL_INTERVAL).unwrap_or(now);
        if next == now {
            break;
        }
    }
    next
}

/// Pad `real` with reads of random boxes up to a multiple of [`POLL_ROUND`] and shuffle, so
/// the number and order of reads don't reveal how many contacts or invites exist.
fn padded_round(real: &[BoxRef]) -> Vec<BoxRef> {
    let mut rng = rand::rng();
    let target = real
        .len()
        .div_ceil(POLL_ROUND)
        .max(1)
        .saturating_mul(POLL_ROUND);
    let mut round = real.to_vec();
    while round.len() < target {
        let mut seed = [0u8; SEED_LEN];
        rng.fill_bytes(&mut seed);
        round.push(BoxRef {
            stream: StreamSeed(seed),
            index: rng.random(),
        });
    }
    round.shuffle(&mut rng);
    round
}

/// Ask for the passphrase until the vault opens (or is created). `None` if the UI closes
/// first.
fn unlock(
    commands: &Receiver<io::Result<UiCmd>>,
    ui: &mut UnixStream,
    data_dir: &Path,
) -> io::Result<Option<(Messenger, Vault)>> {
    loop {
        let new = !Vault::exists(data_dir);
        UiEvent::NeedPassphrase { new }.write_to(ui)?;
        let cmd = match commands.recv() {
            Ok(Ok(cmd)) => cmd,
            Ok(Err(err)) => return Err(err),
            Err(_) => return Ok(None),
        };
        let UiCmd::Unlock { passphrase } = cmd else {
            report(ui, "unlock purple first")?;
            continue;
        };
        let passphrase = Zeroizing::new(passphrase);
        let opened = if new {
            Messenger::new().and_then(|messenger| {
                let snapshot = messenger.to_snapshot()?;
                let vault = Vault::create(data_dir, &passphrase, KdfParams::DEFAULT, &snapshot)?;
                Ok((messenger, vault))
            })
        } else {
            Vault::open(data_dir, &passphrase)
                .and_then(|(vault, snapshot)| Ok((Messenger::from_snapshot(&snapshot)?, vault)))
        };
        match opened {
            Ok(pair) => {
                UiEvent::Unlocked.write_to(ui)?;
                return Ok(Some(pair));
            }
            Err(err) => report(ui, &err.to_string())?,
        }
    }
}

/// Show saved contacts and history.
fn replay(messenger: &Messenger, vault: &Vault, ui: &mut UnixStream) -> io::Result<()> {
    for contact in messenger.contacts() {
        UiEvent::Connected {
            contact: contact.to_owned(),
        }
        .write_to(ui)?;
    }
    for entry in vault.history().map_err(io::Error::other)? {
        let body = clip(&String::from_utf8_lossy(&entry.body), MAX_BODY_LEN);
        let event = if entry.outgoing {
            UiEvent::Sent {
                to: entry.contact,
                body,
            }
        } else {
            UiEvent::Message {
                from: entry.contact,
                body,
            }
        };
        event.write_to(ui)?;
    }
    Ok(())
}

/// Save first, then send packets, then record history and tell the UI. A failed save is
/// fatal: carrying on could reuse keys after a restart.
fn commit(
    effects: Effects,
    messenger: &Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    if effects.changed {
        vault
            .save(&messenger.to_snapshot().map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
    }
    for out in effects.outgoing {
        deliver(net, out)?;
    }
    for entry in &effects.history {
        vault.append(entry).map_err(io::Error::other)?;
    }
    for event in effects.events {
        event.write_to(ui)?;
    }
    Ok(())
}

/// Read UI commands on their own thread so the main loop can poll on a timer. The channel
/// closes when the UI closes its socket.
fn spawn_command_reader(mut ui: UnixStream) -> Receiver<io::Result<UiCmd>> {
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

fn handle(cmd: UiCmd, messenger: &mut Messenger) -> session::Result<Effects> {
    let mut effects = Effects {
        changed: true,
        ..Effects::default()
    };
    match cmd {
        UiCmd::Unlock { .. } => {
            return Err(session::Error::State("already unlocked"));
        }
        UiCmd::ChangePassphrase { .. } => {
            return Err(session::Error::State(
                "passphrase changes are handled by the vault",
            ));
        }
        UiCmd::CreateInvite { contact } => {
            let (invite, bundle) = messenger.create_invite(&contact)?;
            effects.outgoing.push(bundle);
            effects.events.push(UiEvent::InviteCreated {
                contact,
                invite: invite.to_text().to_string(),
            });
        }
        UiCmd::AcceptInvite { contact, invite } => {
            messenger.accept_invite(&contact, Invite::from_text(&invite)?)?;
        }
        UiCmd::Send { contact, body } => {
            let at = now()?;
            effects
                .outgoing
                .push(messenger.send(&contact, body.as_bytes())?);
            effects.history.push(HistoryEntry {
                contact,
                outgoing: true,
                at,
                body: body.into_bytes(),
            });
        }
    }
    Ok(effects)
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

/// Read the next box of every stream `messenger` follows and hand it what turns up.
///
/// Reads go out in waves: the first is padded (see [`padded_round`]), and whenever a box
/// turns up, the stream's following box is read in the next wave. Nothing is written here:
/// replies come back in the effects for [`commit`]. Packets the messenger rejects are
/// skipped and their errors returned; I/O errors with purple-net are fatal.
fn poll(
    net: &mut UnixStream,
    messenger: &mut Messenger,
    now: u64,
) -> io::Result<(Effects, Vec<session::Error>)> {
    let mut effects = Effects::default();
    let mut errors = Vec::new();
    let real = messenger.reads().map_err(io::Error::other)?;
    let followed: HashSet<StreamSeed> = real.iter().map(|at| at.stream).collect();
    let mut wave = padded_round(&real);
    let mut budget = MAX_READS_PER_POLL;
    while !wave.is_empty() {
        budget = budget.saturating_sub(wave.len());
        let mut following = Vec::new();
        for (at, packet) in read_wave(net, &wave)? {
            let Some(packet) = packet else { continue };
            if !followed.contains(&at.stream) {
                continue;
            }
            effects.changed = true;
            match messenger.receive(at, &packet) {
                Ok(step) => {
                    effects.outgoing.extend(step.outgoing);
                    for event in step.events {
                        if let Event::Message { from, body } = &event {
                            effects.history.push(HistoryEntry {
                                contact: from.clone(),
                                outgoing: false,
                                at: now,
                                body: body.clone(),
                            });
                        }
                        effects.events.push(to_ui_event(event));
                    }
                }
                Err(err) => errors.push(err),
            }
            if let Some(index) = at.index.checked_add(1) {
                following.push(BoxRef { index, ..at });
            }
        }
        following.truncate(budget);
        wave = following;
    }
    Ok((effects, errors))
}

/// Send every read in `wave`, then collect the replies, which purple-net sends in order.
fn read_wave(net: &mut UnixStream, wave: &[BoxRef]) -> io::Result<Vec<(BoxRef, Option<Packet>)>> {
    for at in wave {
        NetMsg::Read { at: *at }.write_to(net)?;
    }
    wave.iter()
        .map(|at| match NetMsg::read_from(net)? {
            Some(NetMsg::Found { at: got, packet }) if got == *at => Ok((*at, Some(packet))),
            Some(NetMsg::Empty { at: got }) if got == *at => Ok((*at, None)),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected reply from purple-net",
            )),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "purple-net closed the socket",
            )),
        })
        .collect()
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

fn deliver(net: &mut UnixStream, out: Outgoing) -> io::Result<()> {
    for (at, packet) in out.writes {
        NetMsg::Write { at, packet }.write_to(net)?;
    }
    Ok(())
}

/// Two in-memory messengers connect through an invite and exchange messages. Every packet
/// is sealed for its queue and carried through purple-net.
fn self_test(net: &mut UnixStream) -> io::Result<()> {
    let now = now()?;
    let mut alice = Messenger::new().map_err(io::Error::other)?;
    let mut bob = Messenger::new().map_err(io::Error::other)?;

    // Bob creates an invite and stores his bundle; Alice pastes the invite text.
    let (invite, bundle) = bob.create_invite("alice").map_err(io::Error::other)?;
    deliver(net, bundle)?;
    let pasted = Invite::from_text(&invite.to_text()).map_err(io::Error::other)?;
    alice
        .accept_invite("bob", pasted)
        .map_err(io::Error::other)?;

    let bob_connected = UiEvent::Connected {
        contact: "bob".into(),
    };
    let alice_connected = UiEvent::Connected {
        contact: "alice".into(),
    };
    expect(self_test_poll(net, &mut alice, now)? == [bob_connected])?;
    expect(self_test_poll(net, &mut bob, now)? == [alice_connected])?;

    let to_alice = bob
        .send("alice", b"hello alice")
        .map_err(io::Error::other)?;
    deliver(net, to_alice)?;
    expect(self_test_poll(net, &mut alice, now)? == [message("bob", "hello alice")])?;
    let to_bob = alice.send("bob", b"hello bob").map_err(io::Error::other)?;
    deliver(net, to_bob)?;
    expect(self_test_poll(net, &mut bob, now)? == [message("alice", "hello bob")])?;

    eprintln!("purple-core: self-test ok (invite, hello, messages both ways through purple-net)");
    Ok(())
}

/// [`poll`] for the self-test: no vault, and any rejected packet is a failure.
/// Packets now wait for a send slot in purple-net, so poll until something arrives.
fn self_test_poll(
    net: &mut UnixStream,
    messenger: &mut Messenger,
    now: u64,
) -> io::Result<Vec<UiEvent>> {
    for _ in 0..SELF_TEST_POLLS {
        let (effects, errors) = poll(net, messenger, now)?;
        if let Some(err) = errors.into_iter().next() {
            return Err(io::Error::other(err));
        }
        for out in effects.outgoing {
            deliver(net, out)?;
        }
        if !effects.events.is_empty() {
            return Ok(effects.events);
        }
        thread::sleep(SELF_TEST_WAIT);
    }
    Err(io::Error::other("self-test timed out waiting for a packet"))
}

fn now() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}

fn message(from: &str, body: &str) -> UiEvent {
    UiEvent::Message {
        from: from.into(),
        body: body.into(),
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

/// Log how much of the sandbox the kernel enforced, if not all of it.
fn note_sandbox(report: &Report) {
    if report.landlock != RulesetStatus::FullyEnforced {
        eprintln!(
            "{NAME}: warning: Landlock only {:?} on this kernel",
            report.landlock
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_are_padded_to_a_multiple_of_sixteen_and_keep_every_real_read() {
        for count in [0, 1, 15, 16, 17, 40] {
            let real: Vec<BoxRef> = (0..count)
                .map(|i| BoxRef {
                    stream: StreamSeed([u8::try_from(i).unwrap(); SEED_LEN]),
                    index: 0,
                })
                .collect();
            let round = padded_round(&real);
            assert_eq!(round.len() % POLL_ROUND, 0, "{count}");
            assert!(!round.is_empty());
            assert!(round.len() < count + POLL_ROUND + 1);
            assert!(real.iter().all(|m| round.contains(m)));
        }
    }

    #[test]
    fn grid_skips_missed_slots() {
        let long_ago = Instant::now().checked_sub(POLL_INTERVAL * 5).unwrap();
        let next = next_on_grid(long_ago);
        assert!(next > Instant::now());
        assert!(next <= Instant::now() + POLL_INTERVAL);
    }
}
