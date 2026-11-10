//! purple-data: holds keys and message state. No network access, no display.
//!
//! Normally it serves `purple-lcars`: it asks for the passphrase, unlocks (or creates) the
//! vault in `--data-dir`, replays contacts and history, then handles commands and polls the
//! network every [`POLL_INTERVAL`]. With `--no-ui` it runs an in-memory self-test through
//! `purple-subspace` and exits.
//!
//! Every step that changes state saves the vault before any packet it produced is sent.
//! Otherwise a crash after sending but before saving would restart from an older ratchet
//! state and could reuse a message key.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use landlock::RulesetStatus;
use purple_combadge::torctl::{LauncherMsg, TorCtlMsg};
use purple_combadge::ui::{MAX_BODY_LEN, MAX_ERROR_LEN, UiCmd, UiEvent};
use purple_combadge::{
    BoxRef, CORE_LAUNCHER_FD, CORE_NET_FD, CORE_TORCTL_FD, CORE_UI_FD, NetMsg, Packet, SEED_LEN,
    StreamSeed, inherited_stream,
};
use purple_data::invite::{Invite, StoreRef};
use purple_data::messenger::{Event, Messenger, Outgoing, Rekey, Taken};
use purple_data::session;
use purple_data::tpm::{Sealer, TPM_DEVICE, Tpm};
use purple_data::vault::{GroupSender, HistoryEntry, KdfParams, UnlockedBy, Vault};
use purple_shields::sandbox::{Network, Policy, Report, restrict};
use rand::seq::SliceRandom;
use rand::{Rng, RngCore};
use zeroize::Zeroizing;

mod tor_route;

use tor_route::TorRoute;

const NAME: &str = "purple-data";
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Reads in a poll's first wave come in multiples of this.
const POLL_ROUND: usize = 16;
/// Most reads in flight at once, so padding can't pile up behind a slow transport.
const MAX_READS_IN_FLIGHT: usize = 256;
const SELF_TEST_POLLS: u32 = 200;
const SELF_TEST_WAIT: Duration = Duration::from_millis(100);
const USAGE: &str = "usage: purple-data (--no-ui | --data-dir <dir> --store <store> [--no-read-padding] [--torctl])";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("purple-data: {err}");
            ExitCode::FAILURE
        }
    }
}

enum Mode {
    SelfTest,
    /// Serve the UI with the vault in this directory. `padded` says whether polls are padded
    /// with reads of random boxes; transports that send cover traffic of their own don't
    /// need it.
    Serve {
        data_dir: PathBuf,
        padded: bool,
        /// The store invites name, from the launcher.
        store: StoreRef,
        /// Whether purple-cloak and the launcher's relay socket are on fds 5 and 6.
        torctl: bool,
    },
}

fn parse_args() -> io::Result<Mode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_args_from(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

fn parse_args_from(args: &[&str]) -> io::Result<Mode> {
    match args {
        ["--no-ui"] => Ok(Mode::SelfTest),
        ["--data-dir", dir, "--store", store, rest @ ..] => {
            let (mut padded, mut torctl) = (true, false);
            for flag in rest {
                match *flag {
                    "--no-read-padding" if padded => padded = false,
                    "--torctl" if !torctl => torctl = true,
                    _ => return Err(io::Error::other(USAGE)),
                }
            }
            Ok(Mode::Serve {
                data_dir: PathBuf::from(dir),
                padded,
                store: StoreRef::parse(store).map_err(io::Error::other)?,
                torctl,
            })
        }
        _ => Err(io::Error::other(USAGE)),
    }
}

#[expect(unsafe_code, reason = "adopting the sockets the launcher passed in")]
fn run() -> io::Result<()> {
    purple_shields::harden()?;
    let mode = parse_args()?;
    let writable: Vec<&Path> = match &mode {
        Mode::SelfTest => Vec::new(),
        Mode::Serve { data_dir, .. } => {
            let tpm = Path::new(TPM_DEVICE);
            let mut writable = vec![data_dir.as_path()];
            if tpm.exists() {
                writable.push(tpm);
            }
            writable
        }
    };
    note_sandbox(&restrict(&Policy {
        writable: &writable,
        network: Network::Denied,
    })?);

    // SAFETY: the launcher hands this fd to purple-data and nothing else here uses it.
    let mut net = unsafe { inherited_stream(CORE_NET_FD)? };
    match mode {
        Mode::SelfTest => self_test(&mut net),
        Mode::Serve {
            data_dir,
            padded,
            store,
            torctl,
        } => {
            // SAFETY: the launcher passes this fd only to purple-data; nothing else uses it.
            let ui = unsafe { inherited_stream(CORE_UI_FD)? };
            let route = if torctl {
                // SAFETY: with --torctl the launcher hands this fd to purple-data and
                // nothing else here uses it.
                let to_torctl = unsafe { inherited_stream(CORE_TORCTL_FD)? };
                // SAFETY: as above, for the launcher's own socket.
                let to_launcher = unsafe { inherited_stream(CORE_LAUNCHER_FD)? };
                TorRoute::new(Some(to_torctl), Some(to_launcher))
            } else {
                TorRoute::new(None, None)
            };
            serve_ui(&mut net, ui, &data_dir, Reads::new(padded), store, route)
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

/// What arrives on core's main loop.
enum Input {
    /// A command from the UI, or `None` once it closes its socket.
    Ui(io::Result<Option<UiCmd>>),
    /// A reply from purple-subspace, or `None` once it closes its socket.
    Net(io::Result<Option<NetMsg>>),
    /// A message from purple-cloak, or `None` once it closes its socket.
    Tor(io::Result<Option<TorCtlMsg>>),
    /// A message from the launcher, or `None` once it closes its socket.
    Launcher(io::Result<Option<LauncherMsg>>),
}

/// Unlock the vault, replay what it holds, then serve the UI until it closes its socket.
fn serve_ui(
    net: &mut UnixStream,
    mut ui: UnixStream,
    data_dir: &Path,
    mut reads: Reads,
    store: StoreRef,
    mut route: TorRoute,
) -> io::Result<()> {
    let (inputs_tx, inputs) = mpsc::channel();
    let mut ui_in = ui.try_clone()?;
    spawn_reader(
        move || UiCmd::read_from(&mut ui_in),
        Input::Ui,
        inputs_tx.clone(),
    );
    let mut net_in = net.try_clone()?;
    spawn_reader(
        move || NetMsg::read_from(&mut net_in),
        Input::Net,
        inputs_tx.clone(),
    );
    let (torctl_in, launcher_in) = route.readers()?;
    if let Some(mut t) = torctl_in {
        spawn_reader(
            move || TorCtlMsg::read_from(&mut t),
            Input::Tor,
            inputs_tx.clone(),
        );
    }
    if let Some(mut l) = launcher_in {
        spawn_reader(
            move || LauncherMsg::read_from(&mut l),
            Input::Launcher,
            inputs_tx,
        );
    }
    let Some((mut messenger, mut vault)) = unlock(&inputs, &mut ui, data_dir, &mut route)? else {
        return Ok(());
    };
    eprintln!(
        "purple-data: unlocked; master key protection: {:?}",
        vault.protection()
    );
    messenger.set_store(store);
    replay(&messenger, &vault, &mut ui)?;
    // Before the first tick moves the last-seen times on.
    for (group, creator) in messenger.stale_groups(now()?) {
        UiEvent::GroupNotice {
            text: format!("you may have missed changes in #{group}; ask {creator} to re-add you"),
            group,
        }
        .write_to(&mut ui)?;
    }
    resend_unwritten(&messenger, net)?;

    // Polls run on a fixed clock, never in response to what the user does, so their
    // timing says nothing about activity.
    let mut next_poll = Instant::now();
    loop {
        let wait = next_poll.saturating_duration_since(Instant::now());
        match inputs.recv_timeout(wait) {
            Ok(Input::Ui(Ok(Some(
                cmd @ (UiCmd::ChangePassphrase { .. } | UiCmd::EnrollTpm { .. }),
            )))) => on_key_command(cmd, &messenger, &mut vault, &mut ui)?,
            Ok(Input::Ui(Ok(Some(cmd)))) => {
                on_command(cmd, &mut messenger, &mut vault, net, &mut ui, &mut route)?;
            }
            Ok(Input::Ui(Ok(None))) => return Ok(()),
            Ok(Input::Net(Ok(Some(NetMsg::Written { at })))) => {
                if messenger.written(&at) {
                    let saved = Effects {
                        changed: true,
                        ..Effects::default()
                    };
                    commit(saved, &mut messenger, &mut vault, net, &mut ui)?;
                }
            }
            Ok(Input::Net(Ok(Some(NetMsg::Taken { at })))) => reads.check(net, at)?,
            Ok(Input::Tor(got)) => route.on_torctl(&got, &mut ui)?,
            Ok(Input::Launcher(got)) => route.on_launcher(&got, net, &mut ui)?,
            Ok(Input::Net(Ok(Some(reply)))) => {
                if let Some(answer) = reads.answer(reply)? {
                    answered(answer, &mut messenger, &mut vault, net, &mut ui)?;
                    reads.follow(net, &messenger.reads().map_err(io::Error::other)?)?;
                }
            }
            Ok(Input::Net(Ok(None))) => return Err(net_closed()),
            Ok(Input::Ui(Err(err)) | Input::Net(Err(err))) => return Err(err),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("purple-data's input channel closed"));
            }
        }
        if Instant::now() >= next_poll {
            tick(&mut messenger, &mut vault, net, &mut ui)?;
            reads.poll(net, &messenger.reads().map_err(io::Error::other)?)?;
            next_poll = next_on_grid(next_poll);
        }
    }
}

/// A command about the vault's keys: a new passphrase, or sealing to the TPM.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "serve_ui sends only these two here"
)]
fn on_key_command(
    cmd: UiCmd,
    messenger: &Messenger,
    vault: &mut Vault,
    ui: &mut UnixStream,
) -> io::Result<()> {
    match cmd {
        UiCmd::ChangePassphrase { old, new } => {
            let (old, new) = (Zeroizing::new(old), Zeroizing::new(new));
            let mut tpm = vault.sealed_to_tpm().then(open_tpm).flatten();
            let changed = messenger.to_snapshot().and_then(|snapshot| {
                vault.change_passphrase(
                    &old,
                    &new,
                    KdfParams::DEFAULT,
                    &snapshot,
                    as_sealer(&mut tpm),
                )
            });
            match changed {
                Ok(()) => UiEvent::PassphraseChanged.write_to(ui)?,
                Err(err) => report(ui, &err.to_string())?,
            }
        }
        UiCmd::EnrollTpm { passphrase } => {
            let passphrase = Zeroizing::new(passphrase);
            let enrolled = Tpm::open()
                .map_err(|err| {
                    session::Error::Io(io::Error::other(format!(
                        "can't open {TPM_DEVICE}: {err} (if permission is denied, add \
                         your user to the tss group)"
                    )))
                })
                .and_then(|mut tpm| {
                    let snapshot = messenger.to_snapshot()?;
                    vault.enroll_tpm(&passphrase, KdfParams::DEFAULT, &snapshot, &mut tpm)
                });
            match enrolled {
                Ok(code) => UiEvent::TpmEnrolled {
                    recovery_code: code.to_text().to_string(),
                }
                .write_to(ui)?,
                Err(err) => report(ui, &err.to_string())?,
            }
        }
        _ => {}
    }
    Ok(())
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
    inputs: &Receiver<Input>,
    ui: &mut UnixStream,
    data_dir: &Path,
    route: &mut TorRoute,
) -> io::Result<Option<(Messenger, Vault)>> {
    loop {
        let new = !Vault::exists(data_dir);
        UiEvent::NeedPassphrase { new }.write_to(ui)?;
        let cmd = loop {
            match inputs.recv() {
                Ok(Input::Ui(Ok(Some(cmd)))) => break cmd,
                Ok(Input::Ui(Ok(None))) | Err(_) => return Ok(None),
                Ok(Input::Ui(Err(err)) | Input::Net(Err(err))) => return Err(err),
                Ok(Input::Net(Ok(None))) => return Err(net_closed()),
                // purple-cloak reports how Tor is doing from its first second on, and may
                // stop before unlock; the user can't choose a route yet, so torctl's other
                // messages change nothing here.
                Ok(Input::Tor(got)) => route.on_torctl(&got, ui)?,
                // Nothing has asked the launcher for anything yet.
                Ok(Input::Launcher(_)) => {}
                Ok(Input::Net(Ok(Some(_)))) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "purple-subspace replied before purple-data read anything",
                    ));
                }
            }
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
            let mut tpm = open_tpm();
            Vault::open(data_dir, &passphrase, as_sealer(&mut tpm))
                .and_then(|(vault, snapshot)| Ok((Messenger::from_snapshot(&snapshot)?, vault)))
        };
        match opened {
            Ok(pair) => {
                UiEvent::Unlocked.write_to(ui)?;
                if pair.1.unlocked_by() == UnlockedBy::RecoveryCode {
                    UiEvent::RecoveryUnlocked.write_to(ui)?;
                }
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
    for (group, creator) in messenger.groups() {
        UiEvent::GroupJoined {
            group,
            creator: creator.unwrap_or_default(),
        }
        .write_to(ui)?;
    }
    for entry in vault.history().map_err(io::Error::other)? {
        replayed(entry).write_to(ui)?;
    }
    Ok(())
}

/// How a history entry is shown again at unlock.
fn replayed(entry: HistoryEntry) -> UiEvent {
    let body = clip(&String::from_utf8_lossy(&entry.body), MAX_BODY_LEN);
    match (entry.group_sender, entry.outgoing) {
        (Some(_), true) => UiEvent::GroupSent {
            group: entry.contact,
            body,
        },
        (Some(sender), false) => UiEvent::GroupMessage {
            group: entry.contact,
            from: sender.name,
            verified: sender.verified,
            body,
        },
        (None, true) => UiEvent::Sent {
            to: entry.contact,
            body,
        },
        (None, false) => UiEvent::Message {
            from: entry.contact,
            body,
        },
    }
}

/// Send again whatever the network never confirmed storing. Boxes are write-once, so a
/// packet that did land the first time is still stored just once.
fn resend_unwritten(messenger: &Messenger, net: &mut UnixStream) -> io::Result<()> {
    for (at, packet) in messenger.unwritten() {
        NetMsg::Write {
            at: *at,
            packet: packet.clone(),
        }
        .write_to(net)?;
    }
    Ok(())
}

/// A UI command: an answer to the blocked prompt goes to purple-cloak, anything else to
/// the messenger.
fn on_command(
    cmd: UiCmd,
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
    route: &mut TorRoute,
) -> io::Result<()> {
    if route.choose(&cmd, ui)? {
        return Ok(());
    }
    match handle(cmd, messenger) {
        Ok(effects) => commit(effects, messenger, vault, net, ui),
        Err(err) => report(ui, &err.to_string()),
    }
}

/// Save first, then send packets, then record history and tell the UI. A failed save is
/// fatal: carrying on could reuse keys after a restart. Packets are saved in the
/// messenger's outbox before they go out, so one lost on the way is sent again after a
/// restart.
fn commit(
    effects: Effects,
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    for out in &effects.outgoing {
        messenger.keep_until_written(out);
    }
    if effects.changed || !effects.outgoing.is_empty() {
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

/// Run the groups' key-update timers, saving before anything they produce is sent.
fn tick(
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    let ticked = messenger.tick(now()?);
    // To stderr, not the UI: a group whose timer keeps failing would report every poll.
    // The log file isn't encrypted, so the group's name stays out of it.
    for (_, err) in &ticked.errors {
        eprintln!("purple-data: a group's key update failed: {err}");
    }
    let effects = Effects {
        outgoing: ticked.outgoing,
        changed: ticked.changed,
        ..Effects::default()
    };
    commit(effects, messenger, vault, net, ui)
}

/// Run `read` on its own thread and pass what it returns to `inputs`, wrapped by `wrap`,
/// so the main loop can poll on a timer. Stops after the end of the stream or an error.
fn spawn_reader<T: Send + 'static>(
    mut read: impl FnMut() -> io::Result<Option<T>> + Send + 'static,
    wrap: fn(io::Result<Option<T>>) -> Input,
    inputs: mpsc::Sender<Input>,
) {
    thread::spawn(move || {
        loop {
            let got = read();
            let last = !matches!(got, Ok(Some(_)));
            // If the main loop is gone, so is the reason to read.
            if inputs.send(wrap(got)).is_err() || last {
                return;
            }
        }
    });
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
        UiCmd::ChangePassphrase { .. } | UiCmd::EnrollTpm { .. } => {
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
        UiCmd::Verify { contact } => {
            effects.changed = false;
            let digits = messenger.fingerprint(&contact)?;
            effects
                .events
                .push(UiEvent::Fingerprint { contact, digits });
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
                group_sender: None,
            });
        }
        group @ (UiCmd::GroupNew { .. }
        | UiCmd::GroupAdd { .. }
        | UiCmd::GroupRemove { .. }
        | UiCmd::GroupJoin { .. }
        | UiCmd::GroupLeave { .. }
        | UiCmd::GroupMembers { .. }
        | UiCmd::GroupRekey { .. }
        | UiCmd::GroupSend { .. }) => handle_group(group, messenger, &mut effects)?,
        // serve_ui sends these to purple-subspace before they get here.
        UiCmd::UseDirect | UiCmd::AddBridges { .. } => {
            return Err(session::Error::State("that goes to purple-subspace"));
        }
    }
    Ok(effects)
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "handle passes only group commands here"
)]
fn handle_group(
    cmd: UiCmd,
    messenger: &mut Messenger,
    effects: &mut Effects,
) -> session::Result<()> {
    let notice = |group, text| UiEvent::GroupNotice { group, text };
    match cmd {
        UiCmd::GroupNew { group } => {
            messenger.create_group(&group)?;
            effects.events.push(UiEvent::GroupJoined {
                group,
                creator: String::new(),
            });
        }
        UiCmd::GroupAdd { group, contact } => {
            effects
                .outgoing
                .push(messenger.ask_to_join(&group, &contact)?);
            effects
                .events
                .push(notice(group, format!("asked {contact} to join")));
        }
        UiCmd::GroupRemove { group, member } => {
            let out = messenger.remove_from_group(&group, &member)?;
            let text = if out.is_empty() {
                format!("cancelled the request to {member}")
            } else {
                format!("removing {member}")
            };
            effects.outgoing.extend(out);
            effects.events.push(notice(group, text));
        }
        UiCmd::GroupJoin { creator, group } => {
            effects
                .outgoing
                .push(messenger.join_group(&creator, &group)?);
            effects.events.push(notice(
                group,
                format!("accepted; waiting for {creator} to add you"),
            ));
        }
        UiCmd::GroupLeave { group } => {
            effects.outgoing.extend(messenger.leave_group(&group)?);
            effects.events.push(UiEvent::GroupLeft {
                group,
                reason: "you left".into(),
            });
        }
        UiCmd::GroupMembers { group } => {
            effects.changed = false;
            let members = messenger
                .group_members(&group)?
                .into_iter()
                .map(|member| (member.name, member.verified))
                .collect();
            effects
                .events
                .push(UiEvent::GroupMembers { group, members });
        }
        UiCmd::GroupRekey { group } => {
            let text = match messenger.rekey_group(&group)? {
                Rekey::Proposed(out) => {
                    effects.outgoing.push(out);
                    "key update sent; it takes effect when the creator commits it"
                }
                Rekey::Committed(out) => {
                    effects.outgoing.push(out);
                    "rekeyed: your key and every waiting member update are replaced"
                }
                Rekey::Alone => {
                    effects.changed = false;
                    "nobody else is in the group yet"
                }
            };
            effects.events.push(notice(group, text.into()));
        }
        UiCmd::GroupSend { group, body } => {
            let at = now()?;
            effects
                .outgoing
                .push(messenger.send_group(&group, body.as_bytes())?);
            effects.history.push(HistoryEntry {
                contact: group,
                outgoing: true,
                at,
                body: body.into_bytes(),
                group_sender: Some(GroupSender {
                    name: "me".into(),
                    verified: true,
                }),
            });
        }
        _ => {}
    }
    Ok(())
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

/// Why a read is in flight. Padding has neither flag set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Purpose {
    /// The messenger wants what the box holds.
    real: bool,
    /// A write to this box was reported taken, and core needs to see what's there.
    check: bool,
}

/// A read purple-subspace answered that core wanted for something.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    at: BoxRef,
    packet: Option<Packet>,
    purpose: Purpose,
}

/// Box reads sent to purple-subspace and not yet answered.
///
/// Each box is read at most once at a time; a stream may have several boxes in flight
/// while it reads ahead. A slow transport never holds up the loop. A box that turns up is
/// followed at once by reads of whatever the messenger wants next; an empty one is tried
/// again on the next poll.
struct Reads {
    /// Whether polls are padded with reads of random boxes (see [`padded_round`]).
    padded: bool,
    in_flight: HashMap<BoxRef, Purpose>,
}

impl Reads {
    fn new(padded: bool) -> Self {
        Self {
            padded,
            in_flight: HashMap::new(),
        }
    }

    /// A poll: read each box in `wanted` that isn't already in flight, padded if this
    /// transport needs it.
    fn poll(&mut self, net: &mut impl Write, wanted: &[BoxRef]) -> io::Result<()> {
        if self.in_flight.len() >= MAX_READS_IN_FLIGHT {
            return Ok(());
        }
        let real = self.idle(wanted);
        let round = if self.padded {
            padded_round(&real)
        } else {
            real.clone()
        };
        for at in round {
            let purpose = Purpose {
                real: real.contains(&at),
                check: false,
            };
            self.send(net, at, purpose)?;
        }
        Ok(())
    }

    /// After a box turns up: read what the messenger wants now, without waiting for the
    /// next poll.
    fn follow(&mut self, net: &mut impl Write, wanted: &[BoxRef]) -> io::Result<()> {
        for at in self.idle(wanted) {
            let purpose = Purpose {
                real: true,
                check: false,
            };
            self.send(net, at, purpose)?;
        }
        Ok(())
    }

    /// See what box `at` holds after a write to it was reported taken.
    fn check(&mut self, net: &mut impl Write, at: BoxRef) -> io::Result<()> {
        if let Some(purpose) = self.in_flight.get_mut(&at) {
            purpose.check = true;
            return Ok(());
        }
        let purpose = Purpose {
            real: false,
            check: true,
        };
        self.send(net, at, purpose)
    }

    fn idle(&self, wanted: &[BoxRef]) -> Vec<BoxRef> {
        wanted
            .iter()
            .filter(|at| !self.in_flight.contains_key(at))
            .copied()
            .collect()
    }

    fn send(&mut self, net: &mut impl Write, at: BoxRef, purpose: Purpose) -> io::Result<()> {
        if purpose.real || purpose.check {
            NetMsg::Read { at }.write_to(net)?;
        } else {
            NetMsg::ReadCover { at }.write_to(net)?;
        }
        self.in_flight.insert(at, purpose);
        Ok(())
    }

    /// Match a reply from purple-subspace to its read. Padding gives `None`.
    fn answer(&mut self, reply: NetMsg) -> io::Result<Option<Answer>> {
        let (at, packet) = match reply {
            NetMsg::Found { at, packet } => (at, Some(packet)),
            NetMsg::Empty { at } => (at, None),
            NetMsg::Read { .. }
            | NetMsg::ReadCover { .. }
            | NetMsg::Write { .. }
            | NetMsg::UseDirect => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "purple-subspace sent a message only purple-data may send",
                ));
            }
            NetMsg::Written { .. } | NetMsg::Taken { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a write report isn't a read reply",
                ));
            }
        };
        match self.in_flight.remove(&at) {
            Some(purpose) if purpose == Purpose::default() => Ok(None),
            Some(purpose) => Ok(Some(Answer {
                at,
                packet,
                purpose,
            })),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "purple-subspace answered a read purple-data didn't send",
            )),
        }
    }
}

/// Hand `packet`, read from box `at`, to the messenger. Nothing happens if the messenger
/// stopped reading that box while the read was in flight. A packet the messenger rejects
/// still moves its stream on, so the effects are kept along with the error.
fn receive(
    messenger: &mut Messenger,
    at: BoxRef,
    packet: &Packet,
    now: u64,
) -> io::Result<(Effects, Option<session::Error>)> {
    let mut effects = Effects::default();
    if !messenger.reads().map_err(io::Error::other)?.contains(&at) {
        return Ok((effects, None));
    }
    effects.changed = true;
    let step = match messenger.receive(at, packet) {
        Ok(step) => step,
        Err(err) => return Ok((effects, Some(err))),
    };
    effects.outgoing.extend(step.outgoing);
    for event in step.events {
        if let Event::Message { from, body } = &event {
            effects.history.push(HistoryEntry {
                contact: from.clone(),
                outgoing: false,
                at: now,
                body: body.clone(),
                group_sender: None,
            });
        }
        if let Event::GroupMessage { group, from, body } = &event {
            effects.history.push(HistoryEntry {
                contact: group.clone(),
                outgoing: false,
                at: now,
                body: body.clone(),
                group_sender: Some(GroupSender {
                    name: from.name.clone(),
                    verified: from.verified,
                }),
            });
        }
        effects.events.push(to_ui_event(event));
    }
    Ok((effects, None))
}

/// Act on a read core wanted: settle a taken write, and hand over what was found.
fn answered(
    answer: Answer,
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    let Answer {
        at,
        packet,
        purpose,
    } = answer;
    if purpose.check {
        resolve_taken(at, packet.as_ref(), messenger, vault, net, ui)?;
    }
    match (purpose.real, packet) {
        (true, Some(packet)) => receive_in_order(at, packet, messenger, vault, net, ui)?,
        // An old group stream that stays quiet is dropped; that needs saving.
        (true, None) if messenger.empty(&at, now()?).map_err(io::Error::other)? => {
            let saved = Effects {
                changed: true,
                ..Effects::default()
            };
            commit(saved, messenger, vault, net, ui)?;
        }
        _ => {}
    }
    Ok(())
}

/// Hand the messenger box `at`, then every box read ahead that is now next in its stream.
fn receive_in_order(
    at: BoxRef,
    packet: Packet,
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    let mut pending = Some((at, packet));
    while let Some((box_at, box_packet)) = pending {
        let (effects, error) = receive(messenger, box_at, &box_packet, now()?)?;
        commit(effects, messenger, vault, net, ui)?;
        if let Some(err) = error {
            report(ui, &format!("dropped a packet: {err}"))?;
        }
        pending = messenger.buffered_next().map_err(io::Error::other)?;
    }
    Ok(())
}

/// A write to box `at` was reported taken and the box holds `found`: write again, write
/// elsewhere, or just save that it landed.
fn resolve_taken(
    at: BoxRef,
    found: Option<&Packet>,
    messenger: &mut Messenger,
    vault: &mut Vault,
    net: &mut UnixStream,
    ui: &mut UnixStream,
) -> io::Result<()> {
    let saved = |outgoing| Effects {
        outgoing,
        changed: true,
        ..Effects::default()
    };
    match messenger.taken(&at, found) {
        Ok(Taken::Ours) => {
            eprintln!("purple-data: a box reported full already held this packet");
            commit(saved(Vec::new()), messenger, vault, net, ui)
        }
        Ok(Taken::Resend(again, packet)) => {
            eprintln!("purple-data: a box reported full reads as empty; writing it again");
            NetMsg::Write { at: again, packet }.write_to(net)
        }
        Ok(Taken::Moved(out)) => {
            eprintln!("purple-data: another member filled a box first; moving the packet on");
            commit(saved(vec![out]), messenger, vault, net, ui)
        }
        Ok(Taken::Unknown) => Ok(()),
        Err(err) => {
            commit(saved(Vec::new()), messenger, vault, net, ui)?;
            report(ui, &err.to_string())
        }
    }
}

fn net_closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "purple-subspace closed the socket",
    )
}

fn to_ui_event(event: Event) -> UiEvent {
    match event {
        Event::Connected(contact) => UiEvent::Connected { contact },
        Event::Message { from, body } => UiEvent::Message {
            from,
            body: clip(&String::from_utf8_lossy(&body), MAX_BODY_LEN),
        },
        Event::GroupRequest { creator, group } => UiEvent::GroupRequest { creator, group },
        Event::GroupJoined { group, creator } => UiEvent::GroupJoined {
            group,
            creator: creator.unwrap_or_default(),
        },
        Event::GroupMessage { group, from, body } => UiEvent::GroupMessage {
            group,
            from: from.name,
            verified: from.verified,
            body: clip(&String::from_utf8_lossy(&body), MAX_BODY_LEN),
        },
        Event::GroupNotice { group, text } => UiEvent::GroupNotice {
            group,
            text: clip(&text, MAX_ERROR_LEN),
        },
        Event::GroupLeft { group, reason } => UiEvent::GroupLeft {
            group,
            reason: clip(&reason, MAX_ERROR_LEN),
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
/// is sealed for its queue and carried through purple-subspace.
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

    // Carol connects with Alice; Alice makes a group and adds Bob, then Carol. Bob and
    // Carol aren't each other's contacts. Each step finishes before the next starts, so no
    // two members ever write the same box.
    let mut carol = Messenger::new().map_err(io::Error::other)?;
    let (carol_invite, carol_bundle) = carol.create_invite("alice").map_err(io::Error::other)?;
    deliver(net, carol_bundle)?;
    alice
        .accept_invite("carol", carol_invite)
        .map_err(io::Error::other)?;
    let carol_connected = UiEvent::Connected {
        contact: "carol".into(),
    };
    expect(self_test_poll(net, &mut alice, now)? == [carol_connected])?;
    let carol_sees_alice = UiEvent::Connected {
        contact: "alice".into(),
    };
    expect(self_test_poll(net, &mut carol, now)? == [carol_sees_alice])?;
    alice.create_group("team").map_err(io::Error::other)?;
    self_test_add(net, &mut alice, "bob", &mut bob, now)?;
    self_test_add(net, &mut alice, "carol", &mut carol, now)?;
    expect(self_test_poll(net, &mut bob, now)? == [group_notice("carol joined")])?;

    let to_team = carol
        .send_group("team", b"hello team")
        .map_err(io::Error::other)?;
    deliver(net, to_team)?;
    expect(self_test_poll(net, &mut alice, now)? == [group_message("carol", true)])?;
    expect(self_test_poll(net, &mut bob, now)? == [group_message("carol", false)])?;

    eprintln!(
        "purple-data: level 1 diagnostic ok (invite, hello, messages both ways, a three-member group, \
         through purple-subspace)"
    );
    Ok(())
}

/// Alice asks `member` (her contact `name`) to join "team", and they accept.
fn self_test_add(
    net: &mut UnixStream,
    alice: &mut Messenger,
    name: &str,
    member: &mut Messenger,
    now: u64,
) -> io::Result<()> {
    deliver(
        net,
        alice.ask_to_join("team", name).map_err(io::Error::other)?,
    )?;
    let request = UiEvent::GroupRequest {
        creator: "alice".into(),
        group: "team".into(),
    };
    expect(self_test_poll(net, member, now)? == [request])?;
    deliver(
        net,
        member
            .join_group("alice", "team")
            .map_err(io::Error::other)?,
    )?;
    expect(self_test_poll(net, alice, now)? == [group_notice(&format!("{name} joined"))])?;
    let joined = UiEvent::GroupJoined {
        group: "team".into(),
        creator: "alice".into(),
    };
    expect(self_test_poll(net, member, now)? == [joined])
}

fn group_notice(text: &str) -> UiEvent {
    UiEvent::GroupNotice {
        group: "team".into(),
        text: text.into(),
    }
}

fn group_message(from: &str, verified: bool) -> UiEvent {
    UiEvent::GroupMessage {
        group: "team".into(),
        from: from.into(),
        verified,
        body: "hello team".into(),
    }
}

/// A poll for the self-test, run until every read is answered: no vault, and any rejected
/// packet is a failure. Packets wait for a send slot in purple-subspace, so poll until
/// something arrives.
fn self_test_poll(
    net: &mut UnixStream,
    messenger: &mut Messenger,
    now: u64,
) -> io::Result<Vec<UiEvent>> {
    let mut reads = Reads::new(true);
    for _ in 0..SELF_TEST_POLLS {
        reads.poll(net, &messenger.reads().map_err(io::Error::other)?)?;
        let mut events = Vec::new();
        while !reads.in_flight.is_empty() {
            let reply = NetMsg::read_from(net)?.ok_or_else(net_closed)?;
            if matches!(reply, NetMsg::Written { .. } | NetMsg::Taken { .. }) {
                continue;
            }
            let Some(answer) = reads.answer(reply)? else {
                continue;
            };
            let (true, Some(found)) = (answer.purpose.real, answer.packet) else {
                continue;
            };
            let mut pending = Some((answer.at, found));
            while let Some((at, packet)) = pending {
                let (effects, error) = receive(messenger, at, &packet, now)?;
                if let Some(err) = error {
                    return Err(io::Error::other(err));
                }
                for out in effects.outgoing {
                    deliver(net, out)?;
                }
                events.extend(effects.events);
                pending = messenger.buffered_next().map_err(io::Error::other)?;
            }
            reads.follow(net, &messenger.reads().map_err(io::Error::other)?)?;
        }
        if !events.is_empty() {
            return Ok(events);
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

/// The TPM, if this machine has one this user may use. Vaults not sealed to it don't need
/// it, so a missing TPM isn't an error here.
fn open_tpm() -> Option<Tpm<File>> {
    Tpm::open().ok()
}

fn as_sealer(tpm: &mut Option<Tpm<File>>) -> Option<&mut dyn Sealer> {
    tpm.as_mut().map(|tpm| -> &mut dyn Sealer { tpm })
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
    use purple_combadge::{NetStatus, Route};
    use purple_data::messenger::GroupMember;

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

    fn at(stream: u8, index: u64) -> BoxRef {
        BoxRef {
            stream: StreamSeed([stream; SEED_LEN]),
            index,
        }
    }

    fn sent(out: &mut Vec<u8>) -> Vec<BoxRef> {
        let mut bytes = out.as_slice();
        let reads = std::iter::from_fn(|| NetMsg::read_from(&mut bytes).unwrap())
            .map(|msg| match msg {
                NetMsg::Read { at } | NetMsg::ReadCover { at } => at,
                other @ (NetMsg::Write { .. }
                | NetMsg::Found { .. }
                | NetMsg::Empty { .. }
                | NetMsg::Written { .. }
                | NetMsg::Taken { .. }
                | NetMsg::UseDirect) => {
                    panic!("not a read: {other:?}")
                }
            })
            .collect();
        out.clear();
        reads
    }

    fn real(at: BoxRef, packet: Option<Packet>) -> Answer {
        Answer {
            at,
            packet,
            purpose: Purpose {
                real: true,
                check: false,
            },
        }
    }

    #[test]
    fn unpadded_polls_read_each_wanted_box_once() {
        let mut reads = Reads::new(false);
        let mut net = Vec::new();
        reads
            .poll(&mut net, &[at(1, 0), at(1, 1), at(2, 5)])
            .unwrap();
        assert_eq!(sent(&mut net), [at(1, 0), at(1, 1), at(2, 5)]);

        // All still in flight: the next poll sends nothing.
        reads
            .poll(&mut net, &[at(1, 0), at(1, 1), at(2, 5)])
            .unwrap();
        assert!(sent(&mut net).is_empty());

        let packet = Packet::from_slice(&[7; purple_combadge::PACKET_LEN]).unwrap();
        let got = reads
            .answer(NetMsg::Found {
                at: at(1, 0),
                packet: packet.clone(),
            })
            .unwrap();
        assert_eq!(got, Some(real(at(1, 0), Some(packet))));
        reads
            .follow(&mut net, &[at(1, 1), at(1, 2), at(2, 5)])
            .unwrap();
        assert_eq!(sent(&mut net), [at(1, 2)]);

        assert_eq!(
            reads.answer(NetMsg::Empty { at: at(2, 5) }).unwrap(),
            Some(real(at(2, 5), None))
        );
    }

    #[test]
    fn checks_ride_along_with_reads_already_in_flight() {
        let mut reads = Reads::new(false);
        let mut net = Vec::new();
        reads.poll(&mut net, &[at(1, 0)]).unwrap();
        sent(&mut net);
        reads.check(&mut net, at(1, 0)).unwrap();
        assert!(sent(&mut net).is_empty(), "no second read of the same box");
        reads.check(&mut net, at(3, 9)).unwrap();
        assert_eq!(sent(&mut net), [at(3, 9)]);

        let both = reads
            .answer(NetMsg::Empty { at: at(1, 0) })
            .unwrap()
            .unwrap();
        assert_eq!(
            both.purpose,
            Purpose {
                real: true,
                check: true
            }
        );
        let check = reads
            .answer(NetMsg::Empty { at: at(3, 9) })
            .unwrap()
            .unwrap();
        assert_eq!(
            check.purpose,
            Purpose {
                real: false,
                check: true
            }
        );
    }

    #[test]
    fn padded_polls_hide_padding_from_the_caller() {
        let mut reads = Reads::new(true);
        let mut net = Vec::new();
        reads.poll(&mut net, &[at(1, 0)]).unwrap();
        let round = sent(&mut net);
        assert_eq!(round.len(), POLL_ROUND);
        for read in round {
            let got = reads.answer(NetMsg::Empty { at: read }).unwrap();
            if read == at(1, 0) {
                assert_eq!(got, Some(real(read, None)));
            } else {
                assert_eq!(got, None);
            }
        }
        assert!(reads.in_flight.is_empty());
    }

    #[test]
    fn torctl_gone_during_unlock_is_told() {
        let dir = std::env::temp_dir().join(format!("purple-unlock-gone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        tx.send(Input::Tor(Ok(None))).unwrap();
        tx.send(Input::Ui(Ok(None))).unwrap();
        let (mut ui, mut ui_peer) = UnixStream::pair().unwrap();
        let (to_torctl, _torctl) = UnixStream::pair().unwrap();
        let mut route = TorRoute::new(Some(to_torctl), None);
        assert!(unlock(&rx, &mut ui, &dir, &mut route).unwrap().is_none());
        drop(ui);
        assert_eq!(
            UiEvent::read_from(&mut ui_peer).unwrap(),
            Some(UiEvent::NeedPassphrase { new: true })
        );
        assert_eq!(
            UiEvent::read_from(&mut ui_peer).unwrap(),
            Some(UiEvent::Notice {
                text: tor_route::TORCTL_GONE.into()
            })
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_from_torctl_during_unlock_goes_to_the_ui() {
        let dir = std::env::temp_dir().join(format!("purple-unlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (tx, rx) = mpsc::channel();
        let status = NetStatus::Connecting {
            route: Route::Tor,
            percent: 5,
        };
        tx.send(Input::Tor(Ok(Some(TorCtlMsg::Status(status)))))
            .unwrap();
        tx.send(Input::Ui(Ok(None))).unwrap();
        let (mut ui, mut ui_peer) = UnixStream::pair().unwrap();
        assert!(
            unlock(&rx, &mut ui, &dir, &mut TorRoute::new(None, None))
                .unwrap()
                .is_none()
        );
        drop(ui);
        assert_eq!(
            UiEvent::read_from(&mut ui_peer).unwrap(),
            Some(UiEvent::NeedPassphrase { new: true })
        );
        assert_eq!(
            UiEvent::read_from(&mut ui_peer).unwrap(),
            Some(UiEvent::Network { status })
        );
        assert_eq!(
            UiEvent::read_from(&mut ui_peer).unwrap(),
            None,
            "asked once"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_store_arg() {
        assert!(matches!(
            parse_args_from(&["--data-dir", "/d", "--store", "dev"]).unwrap(),
            Mode::Serve {
                store: StoreRef::Dev,
                padded: true,
                ..
            }
        ));
        assert!(matches!(
            parse_args_from(&[
                "--data-dir",
                "/d",
                "--store",
                "namenlos",
                "--no-read-padding"
            ])
            .unwrap(),
            Mode::Serve {
                store: StoreRef::Namenlos,
                padded: false,
                ..
            }
        ));
        assert!(
            parse_args_from(&["--data-dir", "/d"]).is_err(),
            "--store is required"
        );
        assert!(matches!(
            parse_args_from(&["--data-dir", "/d", "--store", "tor:x.onion", "--torctl"]).unwrap(),
            Mode::Serve {
                torctl: true,
                padded: true,
                ..
            }
        ));
        assert!(
            parse_args_from(&["--data-dir", "/d", "--store", "dev", "--torctl", "--torctl"])
                .is_err()
        );
    }

    #[test]
    fn padding_reads_go_out_as_cover_reads() {
        let mut reads = Reads::new(true);
        let mut wire = Vec::new();
        reads.poll(&mut wire, &[at(1, 0)]).unwrap();
        let mut r = &wire[..];
        let (mut plain, mut cover) = (0, 0);
        while let Some(msg) = NetMsg::read_from(&mut r).unwrap() {
            if let NetMsg::Read { at: read } = msg {
                assert_eq!(read, at(1, 0));
                plain += 1;
            } else {
                assert!(
                    matches!(msg, NetMsg::ReadCover { .. }),
                    "unexpected {msg:?}"
                );
                cover += 1;
            }
        }
        assert_eq!((plain, cover), (1, POLL_ROUND - 1));
    }

    #[test]
    fn replies_to_reads_core_never_sent_are_refused() {
        let mut reads = Reads::new(false);
        assert!(reads.answer(NetMsg::Empty { at: at(1, 0) }).is_err());
        let mut net = Vec::new();
        reads.poll(&mut net, &[at(1, 0)]).unwrap();
        assert!(reads.answer(NetMsg::Empty { at: at(1, 0) }).is_ok());
        assert!(
            reads.answer(NetMsg::Empty { at: at(1, 0) }).is_err(),
            "answered twice"
        );
    }

    #[test]
    fn group_events_reach_the_ui_with_their_sender() {
        let joined = to_ui_event(Event::GroupJoined {
            group: "team".into(),
            creator: None,
        });
        assert_eq!(
            joined,
            UiEvent::GroupJoined {
                group: "team".into(),
                creator: String::new()
            }
        );
        let said = to_ui_event(Event::GroupMessage {
            group: "team".into(),
            from: GroupMember {
                name: "dana".into(),
                verified: false,
            },
            body: b"hi".to_vec(),
        });
        assert_eq!(
            said,
            UiEvent::GroupMessage {
                group: "team".into(),
                from: "dana".into(),
                verified: false,
                body: "hi".into()
            }
        );
    }

    #[test]
    fn replayed_history_tells_groups_from_contacts() {
        let entry = |outgoing, group_sender| HistoryEntry {
            contact: "team".into(),
            outgoing,
            at: 1,
            body: b"hi".to_vec(),
            group_sender,
        };
        let dana = GroupSender {
            name: "dana".into(),
            verified: false,
        };
        let me = GroupSender {
            name: "me".into(),
            verified: true,
        };
        assert_eq!(
            replayed(entry(false, Some(dana))),
            UiEvent::GroupMessage {
                group: "team".into(),
                from: "dana".into(),
                verified: false,
                body: "hi".into()
            }
        );
        assert_eq!(
            replayed(entry(true, Some(me))),
            UiEvent::GroupSent {
                group: "team".into(),
                body: "hi".into()
            }
        );
        assert_eq!(
            replayed(entry(false, None)),
            UiEvent::Message {
                from: "team".into(),
                body: "hi".into()
            }
        );
    }

    #[test]
    fn group_commands_change_the_messenger_and_tell_the_ui() {
        let mut messenger = Messenger::new().unwrap();
        let created = handle(
            UiCmd::GroupNew {
                group: "team".into(),
            },
            &mut messenger,
        )
        .unwrap();
        assert!(created.changed);
        assert_eq!(
            created.events,
            [UiEvent::GroupJoined {
                group: "team".into(),
                creator: String::new()
            }]
        );

        let sent = handle(
            UiCmd::GroupSend {
                group: "team".into(),
                body: "hi".into(),
            },
            &mut messenger,
        )
        .unwrap();
        assert_eq!(sent.outgoing.len(), 1);
        let entry = &sent.history[0];
        assert_eq!(entry.contact, "team");
        assert!(entry.outgoing);
        assert_eq!(
            entry.group_sender,
            Some(GroupSender {
                name: "me".into(),
                verified: true
            })
        );

        let members = handle(
            UiCmd::GroupMembers {
                group: "team".into(),
            },
            &mut messenger,
        )
        .unwrap();
        assert!(!members.changed, "listing members changes nothing");
        assert_eq!(
            members.events,
            [UiEvent::GroupMembers {
                group: "team".into(),
                members: vec![("me".into(), true)]
            }]
        );

        let rekeyed = handle(
            UiCmd::GroupRekey {
                group: "team".into(),
            },
            &mut messenger,
        )
        .unwrap();
        assert!(rekeyed.outgoing.is_empty());
        assert_eq!(
            rekeyed.events,
            [UiEvent::GroupNotice {
                group: "team".into(),
                text: "nobody else is in the group yet".into(),
            }]
        );

        assert!(
            handle(
                UiCmd::GroupAdd {
                    group: "team".into(),
                    contact: "nobody".into(),
                },
                &mut messenger,
            )
            .is_err()
        );
        let left = handle(
            UiCmd::GroupLeave {
                group: "team".into(),
            },
            &mut messenger,
        )
        .unwrap();
        assert!(left.outgoing.is_empty(), "the creator tells nobody");
        assert!(messenger.groups().is_empty());
    }

    #[test]
    fn grid_skips_missed_slots() {
        let long_ago = Instant::now().checked_sub(POLL_INTERVAL * 5).unwrap();
        let next = next_on_grid(long_ago);
        assert!(next > Instant::now());
        assert!(next <= Instant::now() + POLL_INTERVAL);
    }
}
