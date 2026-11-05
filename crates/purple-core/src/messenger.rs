//! The messenger: contacts, invites and queues on top of [`Account`].
//!
//! It never touches the network. Callers ask which boxes to read next, hand it every
//! packet they find there, and write the boxes it returns.
//!
//! Connecting: the inviter writes a prekey bundle to the invite's bundle stream. The
//! accepter reads it, starts a session, and writes a hello to the invite's intro stream
//! carrying fresh secrets for both directions. From then on each direction is its own
//! stream of write-once boxes, read in order.

use std::collections::{BTreeMap, HashMap};

use purple_ipc::{BoxRef, Packet, StreamSeed};
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::content::Content;
use crate::fragment::{Reassembler, split};
use crate::invite::Invite;
use crate::queue::{Queue, QueueSecret};
use crate::session::{Account, Error, Result};

/// Boxes to write.
#[derive(Debug, Default)]
pub struct Outgoing {
    /// Each box and the sealed packet that goes in it, in stream order.
    pub writes: Vec<(BoxRef, Packet)>,
}

/// Something the user should see.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// An invite was completed with this contact.
    Connected(String),
    /// A text message arrived.
    Message {
        /// Contact it came from.
        from: String,
        /// Message text.
        body: Vec<u8>,
    },
}

/// The result of handling one packet.
#[derive(Debug, Default)]
pub struct Step {
    /// Events for the user.
    pub events: Vec<Event>,
    /// Boxes to write.
    pub outgoing: Vec<Outgoing>,
}

struct Contact {
    send: QueueSecret,
    receive: QueueSecret,
    /// Next box this side writes on the send stream.
    next_send: u64,
    /// Next box this side reads on the receive stream.
    next_read: u64,
}

/// An invite waiting for something to arrive on one of its streams.
struct Pending {
    invite: Invite,
    next_read: u64,
}

enum Route {
    Bundle(String),
    Intro(String),
    Contact(String),
}

/// One user's contacts and conversations.
pub struct Messenger {
    account: Account,
    contacts: BTreeMap<String, Contact>,
    /// Invites this user created, waiting for the accepter's hello on the intro stream.
    invites: BTreeMap<String, Pending>,
    /// Invites this user accepted, waiting for the inviter's bundle on the bundle stream.
    accepting: BTreeMap<String, Pending>,
    reassemblers: HashMap<StreamSeed, Reassembler>,
    /// Packets handed to the network that it hasn't confirmed storing yet. Kept in the
    /// snapshot, so they're sent again after a restart.
    outbox: Vec<(BoxRef, Packet)>,
}

impl std::fmt::Debug for Messenger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Messenger").finish_non_exhaustive()
    }
}

impl Messenger {
    /// A messenger with a fresh identity and no contacts.
    ///
    /// # Errors
    /// Fails if the account can't be created.
    pub fn new() -> Result<Self> {
        Ok(Self {
            account: Account::generate()?,
            contacts: BTreeMap::new(),
            invites: BTreeMap::new(),
            accepting: BTreeMap::new(),
            reassemblers: HashMap::new(),
            outbox: Vec::new(),
        })
    }

    /// Create an invite for a contact who will be known as `contact`. Returns the invite to
    /// show as a QR code or link, and the bundle boxes to write.
    ///
    /// # Errors
    /// Fails if `contact` is already in use, or generating the prekeys fails.
    pub fn create_invite(&mut self, contact: &str) -> Result<(Invite, Outgoing)> {
        self.check_name_free(contact)?;
        let (invite, bundle) = self.account.create_invite()?;
        let (outgoing, _) = outgoing(&invite.bundle_queue()?, 0, &bundle)?;
        self.invites.insert(
            contact.to_owned(),
            Pending {
                invite: invite.clone(),
                next_read: 0,
            },
        );
        Ok((invite, outgoing))
    }

    /// Accept a scanned invite from a contact who will be known as `contact`. The session
    /// starts once the inviter's bundle arrives through [`Self::receive`].
    ///
    /// # Errors
    /// Fails if `contact` is already in use.
    pub fn accept_invite(&mut self, contact: &str, invite: Invite) -> Result<()> {
        self.check_name_free(contact)?;
        self.accepting.insert(
            contact.to_owned(),
            Pending {
                invite,
                next_read: 0,
            },
        );
        Ok(())
    }

    /// The next box to read on every stream this messenger receives on.
    ///
    /// # Errors
    /// Fails only if queue derivation fails.
    pub fn reads(&self) -> Result<Vec<BoxRef>> {
        let mut out = Vec::new();
        for pending in self.accepting.values() {
            out.push(BoxRef {
                stream: pending.invite.bundle_queue()?.stream(),
                index: pending.next_read,
            });
        }
        for pending in self.invites.values() {
            out.push(BoxRef {
                stream: pending.invite.intro_queue()?.stream(),
                index: pending.next_read,
            });
        }
        for contact in self.contacts.values() {
            out.push(BoxRef {
                stream: contact.receive.queue()?.stream(),
                index: contact.next_read,
            });
        }
        Ok(out)
    }

    /// Handle the packet read from box `at`, which must be the next box of one of the
    /// streams in [`Self::reads`].
    ///
    /// The stream moves on to the next box even if this packet turns out to be forged or
    /// malformed, so one bad box can't block the stream.
    ///
    /// # Errors
    /// Fails if `at` isn't the next box of a stream this messenger reads, or the packet is
    /// forged, malformed or replayed.
    pub fn receive(&mut self, at: BoxRef, packet: &Packet) -> Result<Step> {
        let (route, queue) = self.route(at)?;
        self.advance(&route)?;
        let fragment = queue.open(at.index, packet)?;
        let Some(message) = self
            .reassemblers
            .entry(at.stream)
            .or_default()
            .push(&fragment)?
        else {
            return Ok(Step::default());
        };
        match route {
            Route::Bundle(name) => self.finish_accept(&name, at.stream, &message),
            Route::Intro(name) => self.finish_invite(&name, at.stream, &message),
            Route::Contact(name) => self.deliver(&name, &message),
        }
    }

    /// Encrypt a text message for `contact`.
    ///
    /// # Errors
    /// Fails if `contact` isn't a connected contact.
    pub fn send(&mut self, contact: &str, body: &[u8]) -> Result<Outgoing> {
        let known = self
            .contacts
            .get(contact)
            .ok_or(Error::State("unknown contact"))?;
        let queue = known.send.queue()?;
        let first = known.next_send;
        let wire = self
            .account
            .encrypt(contact, &Content::Text(body.to_vec()).encode())?;
        let (out, next) = outgoing(&queue, first, &wire)?;
        if let Some(state) = self.contacts.get_mut(contact) {
            state.next_send = next;
        }
        Ok(out)
    }

    /// Keep `out`'s packets until the network confirms each one with [`Self::written`].
    pub fn keep_until_written(&mut self, out: &Outgoing) {
        self.outbox.extend(out.writes.iter().cloned());
    }

    /// The network stored box `at`: stop keeping its packet. Returns whether one was kept.
    pub fn written(&mut self, at: &BoxRef) -> bool {
        let before = self.outbox.len();
        self.outbox.retain(|(kept, _)| kept != at);
        self.outbox.len() != before
    }

    /// Packets the network hasn't confirmed storing, oldest first.
    #[must_use]
    pub fn unwritten(&self) -> &[(BoxRef, Packet)] {
        &self.outbox
    }

    /// Serialize everything needed to resume: the account (identity, prekeys, sessions),
    /// contacts with their queue secrets and stream positions, pending invites, and packets
    /// not yet confirmed stored. Partly reassembled messages aren't kept.
    ///
    /// # Errors
    /// Fails only if libsignal can't serialize a record.
    pub fn to_snapshot(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut w = Writer::default();
        w.u8(SNAPSHOT_VERSION);
        self.account.encode(&mut w)?;
        w.len(self.contacts.len())?;
        for (name, contact) in &self.contacts {
            w.bytes(name.as_bytes())?;
            w.bytes(contact.send.as_bytes())?;
            w.bytes(contact.receive.as_bytes())?;
            w.u64(contact.next_send);
            w.u64(contact.next_read);
        }
        for invites in [&self.invites, &self.accepting] {
            w.len(invites.len())?;
            for (name, pending) in invites {
                w.bytes(name.as_bytes())?;
                w.bytes(&pending.invite.encode())?;
                w.u64(pending.next_read);
            }
        }
        w.len(self.outbox.len())?;
        for (at, packet) in &self.outbox {
            w.bytes(&at.stream.0)?;
            w.u64(at.index);
            w.bytes(packet.as_bytes())?;
        }
        Ok(w.finish())
    }

    /// Restore a messenger from [`Self::to_snapshot`], or from a version 2 snapshot,
    /// which had no outbox.
    ///
    /// # Errors
    /// Fails on an unknown version or any malformed field.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != SNAPSHOT_VERSION && version != 2 {
            return Err(Error::Malformed("unknown snapshot version"));
        }
        let account = Account::decode(&mut r)?;
        let mut contacts = BTreeMap::new();
        for _ in 0..r.len()? {
            let name = r.string()?;
            let contact = Contact {
                send: secret(r.bytes()?)?,
                receive: secret(r.bytes()?)?,
                next_send: r.u64()?,
                next_read: r.u64()?,
            };
            contacts.insert(name, contact);
        }
        let invites = read_pending(&mut r)?;
        let accepting = read_pending(&mut r)?;
        let mut outbox = Vec::new();
        if version == SNAPSHOT_VERSION {
            for _ in 0..r.len()? {
                let stream = StreamSeed(
                    r.bytes()?
                        .try_into()
                        .map_err(|_| Error::Malformed("stream seed has the wrong length"))?,
                );
                let at = BoxRef {
                    stream,
                    index: r.u64()?,
                };
                outbox.push((at, Packet::from_slice(r.bytes()?)?));
            }
        }
        r.finish()?;
        Ok(Self {
            account,
            contacts,
            invites,
            accepting,
            reassemblers: HashMap::new(),
            outbox,
        })
    }

    /// Names of connected contacts.
    pub fn contacts(&self) -> impl Iterator<Item = &str> {
        self.contacts.keys().map(String::as_str)
    }

    fn finish_accept(&mut self, name: &str, stream: StreamSeed, bundle: &[u8]) -> Result<Step> {
        let invite = self
            .accepting
            .get(name)
            .ok_or(Error::State("no pending accept"))?
            .invite
            .clone();
        self.account.accept_invite(name, &invite, bundle)?;

        let to_inviter = QueueSecret::random()?;
        let to_accepter = QueueSecret::random()?;
        let hello = Content::Hello {
            to_inviter: to_inviter.clone(),
            to_accepter: to_accepter.clone(),
        };
        let wire = self.account.encrypt(name, &hello.encode())?;
        let (intro, _) = outgoing(&invite.intro_queue()?, 0, &wire)?;

        self.accepting.remove(name);
        self.reassemblers.remove(&stream);
        self.contacts.insert(
            name.to_owned(),
            Contact {
                send: to_inviter,
                receive: to_accepter,
                next_send: 0,
                next_read: 0,
            },
        );
        Ok(Step {
            events: vec![Event::Connected(name.to_owned())],
            outgoing: vec![intro],
        })
    }

    fn finish_invite(&mut self, name: &str, stream: StreamSeed, wire: &[u8]) -> Result<Step> {
        let Content::Hello {
            to_inviter,
            to_accepter,
        } = Content::decode(&self.account.decrypt(name, wire)?)?
        else {
            return Err(Error::Malformed("expected a hello on the intro stream"));
        };
        self.invites.remove(name);
        self.reassemblers.remove(&stream);
        self.contacts.insert(
            name.to_owned(),
            Contact {
                send: to_accepter,
                receive: to_inviter,
                next_send: 0,
                next_read: 0,
            },
        );
        Ok(Step {
            events: vec![Event::Connected(name.to_owned())],
            outgoing: Vec::new(),
        })
    }

    fn deliver(&mut self, name: &str, wire: &[u8]) -> Result<Step> {
        match Content::decode(&self.account.decrypt(name, wire)?)? {
            Content::Text(body) => Ok(Step {
                events: vec![Event::Message {
                    from: name.to_owned(),
                    body,
                }],
                outgoing: Vec::new(),
            }),
            Content::Hello { .. } => Err(Error::Malformed("unexpected hello")),
        }
    }

    /// Find which stream box `at` belongs to, and check it's that stream's next box.
    fn route(&self, at: BoxRef) -> Result<(Route, Queue)> {
        let mut found = None;
        for (name, pending) in &self.accepting {
            let queue = pending.invite.bundle_queue()?;
            if queue.stream() == at.stream {
                found = Some((Route::Bundle(name.clone()), queue, pending.next_read));
            }
        }
        for (name, pending) in &self.invites {
            let queue = pending.invite.intro_queue()?;
            if queue.stream() == at.stream {
                found = Some((Route::Intro(name.clone()), queue, pending.next_read));
            }
        }
        for (name, contact) in &self.contacts {
            let queue = contact.receive.queue()?;
            if queue.stream() == at.stream {
                found = Some((Route::Contact(name.clone()), queue, contact.next_read));
            }
        }
        let (route, queue, next) = found.ok_or(Error::State(
            "packet for a stream this messenger doesn't read",
        ))?;
        if at.index != next {
            return Err(Error::State("box read out of order"));
        }
        Ok((route, queue))
    }

    fn advance(&mut self, route: &Route) -> Result<()> {
        let next_read = match route {
            Route::Bundle(name) => self.accepting.get_mut(name).map(|p| &mut p.next_read),
            Route::Intro(name) => self.invites.get_mut(name).map(|p| &mut p.next_read),
            Route::Contact(name) => self.contacts.get_mut(name).map(|c| &mut c.next_read),
        }
        .ok_or(Error::State("stream vanished"))?;
        *next_read = next_read
            .checked_add(1)
            .ok_or(Error::State("stream index exhausted"))?;
        Ok(())
    }

    fn check_name_free(&self, name: &str) -> Result<()> {
        if !valid_name(name) {
            return Err(Error::State(
                "contact names are 1 to 32 characters: letters, digits, - and _",
            ));
        }
        if self.contacts.contains_key(name)
            || self.invites.contains_key(name)
            || self.accepting.contains_key(name)
        {
            return Err(Error::State("contact name already in use"));
        }
        Ok(())
    }
}

const SNAPSHOT_VERSION: u8 = 3;

fn secret(bytes: &[u8]) -> Result<QueueSecret> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Malformed("queue secret has the wrong length"))?;
    Ok(QueueSecret::from_bytes(Zeroizing::new(array)))
}

fn read_pending(r: &mut Reader<'_>) -> Result<BTreeMap<String, Pending>> {
    let mut out = BTreeMap::new();
    for _ in 0..r.len()? {
        let name = r.string()?;
        let pending = Pending {
            invite: Invite::decode(r.bytes()?)?,
            next_read: r.u64()?,
        };
        out.insert(name, pending);
    }
    Ok(out)
}

/// Longest contact name, in characters.
pub const MAX_NAME_CHARS: usize = 32;

/// Contact names are local labels: 1 to [`MAX_NAME_CHARS`] ASCII letters, digits, `-` and
/// `_`. Keeping them plain means they are always safe to show in a terminal.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_CHARS).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Fragment `message`, seal each fragment for consecutive boxes from `first`. Returns the
/// writes and the index after the last box used.
fn outgoing(queue: &Queue, first: u64, message: &[u8]) -> Result<(Outgoing, u64)> {
    let mut index = first;
    let mut writes = Vec::new();
    for fragment in split(message)? {
        let at = BoxRef {
            stream: queue.stream(),
            index,
        };
        writes.push((at, queue.seal(index, &fragment)?));
        index = index
            .checked_add(1)
            .ok_or(Error::State("stream index exhausted"))?;
    }
    Ok((Outgoing { writes }, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory box store: write-once, reads don't consume.
    #[derive(Default)]
    struct Provider(HashMap<BoxRef, Packet>);

    impl Provider {
        fn deliver(&mut self, out: Outgoing) {
            for (at, packet) in out.writes {
                self.0.entry(at).or_insert(packet);
            }
        }

        /// Read every stream `m` follows until nothing new turns up, writing what it sends.
        fn poll(&mut self, m: &mut Messenger) -> Vec<Event> {
            let mut events = Vec::new();
            loop {
                let mut progressed = false;
                for at in m.reads().unwrap() {
                    if let Some(packet) = self.0.get(&at).cloned() {
                        progressed = true;
                        let step = m.receive(at, &packet).unwrap();
                        events.extend(step.events);
                        for out in step.outgoing {
                            self.deliver(out);
                        }
                    }
                }
                if !progressed {
                    return events;
                }
            }
        }
    }

    fn connected(provider: &mut Provider) -> (Messenger, Messenger) {
        let mut alice = Messenger::new().unwrap();
        let mut bob = Messenger::new().unwrap();
        let (invite, bundle) = bob.create_invite("alice").unwrap();
        provider.deliver(bundle);
        alice
            .accept_invite("bob", Invite::decode(&invite.encode()).unwrap())
            .unwrap();
        assert_eq!(provider.poll(&mut alice), [Event::Connected("bob".into())]);
        assert_eq!(provider.poll(&mut bob), [Event::Connected("alice".into())]);
        (alice, bob)
    }

    fn text(from: &str, body: &[u8]) -> Event {
        Event::Message {
            from: from.into(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn invite_then_messages_both_ways() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);

        provider.deliver(alice.send("bob", b"hi bob").unwrap());
        assert_eq!(provider.poll(&mut bob), [text("alice", b"hi bob")]);
        provider.deliver(bob.send("alice", b"hi alice").unwrap());
        assert_eq!(provider.poll(&mut alice), [text("bob", b"hi alice")]);

        // A message spanning several boxes.
        let long = vec![b'x'; 10_000];
        let out = alice.send("bob", &long).unwrap();
        assert!(out.writes.len() > 1);
        provider.deliver(out);
        assert_eq!(provider.poll(&mut bob), [text("alice", &long)]);
    }

    #[test]
    fn messages_fill_consecutive_boxes_of_one_stream() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let first = alice.send("bob", b"one").unwrap();
        let second = alice.send("bob", b"two").unwrap();
        // The first message carries libsignal's PreKey fields and may take two boxes.
        let (a, b) = (first.writes.last().unwrap().0, second.writes[0].0);
        assert_eq!(a.stream, b.stream);
        assert_eq!(b.index, a.index + 1);

        // Delivered out of order, read in order.
        provider.deliver(second);
        assert!(provider.poll(&mut bob).is_empty());
        provider.deliver(first);
        assert_eq!(
            provider.poll(&mut bob),
            [text("alice", b"one"), text("alice", b"two")]
        );
    }

    #[test]
    fn boxes_hold_only_sealed_packets() {
        // Nothing the provider stores contains plaintext or libsignal's cleartext PreKey
        // fields: every packet opens only with the queue key.
        let mut provider = Provider::default();
        let (mut alice, _bob) = connected(&mut provider);
        let out = alice.send("bob", b"secret words").unwrap();
        for (at, packet) in &out.writes {
            assert!(!packet.as_bytes().windows(12).any(|w| w == b"secret words"));
            let stranger = QueueSecret::random().unwrap().queue().unwrap();
            assert!(stranger.open(at.index, packet).is_err());
        }
    }

    #[test]
    fn rejects_boxes_out_of_order_or_on_unknown_streams() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let out = alice.send("bob", b"x").unwrap();
        let (at, packet) = out.writes[0].clone();
        let skipped = BoxRef {
            index: at.index + 1,
            ..at
        };
        assert!(bob.receive(skipped, &packet).is_err());
        assert!(alice.receive(at, &packet).is_err());
        let mut events = Vec::new();
        for (box_at, box_packet) in &out.writes {
            events.extend(bob.receive(*box_at, box_packet).unwrap().events);
        }
        assert_eq!(events, [text("alice", b"x")]);
    }

    #[test]
    fn planted_bundle_is_rejected() {
        // Someone who saw the QR code can fill the bundle stream first. Boxes are
        // write-once, so the invite then fails (a denial of service), but Alice never
        // starts a session with the impostor.
        let mut provider = Provider::default();
        let mut alice = Messenger::new().unwrap();
        let mut bob = Messenger::new().unwrap();
        let (invite, bundle) = bob.create_invite("alice").unwrap();
        let (_, mallory_bundle) = Account::generate().unwrap().create_invite().unwrap();
        let (planted, _) = outgoing(&invite.bundle_queue().unwrap(), 0, &mallory_bundle).unwrap();
        provider.deliver(planted);
        provider.deliver(bundle);
        alice.accept_invite("bob", invite).unwrap();

        let mut errors = 0;
        for at in alice.reads().unwrap() {
            let mut at = at;
            while let Some(packet) = provider.0.get(&at).cloned() {
                errors += usize::from(alice.receive(at, &packet).is_err());
                at.index += 1;
            }
        }
        assert_eq!(errors, 1);
        assert_eq!(alice.contacts().count(), 0);
    }

    #[test]
    fn snapshot_restores_contacts_positions_and_pending_invites() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        provider.deliver(alice.send("bob", b"before").unwrap());
        assert_eq!(provider.poll(&mut bob), [text("alice", b"before")]);
        let (invite, bundle) = bob.create_invite("carol").unwrap();
        provider.deliver(bundle);

        // Both restart from snapshots, then keep talking on the same streams.
        let mut alice = Messenger::from_snapshot(&alice.to_snapshot().unwrap()).unwrap();
        let mut bob = Messenger::from_snapshot(&bob.to_snapshot().unwrap()).unwrap();
        provider.deliver(alice.send("bob", b"after restart").unwrap());
        assert_eq!(provider.poll(&mut bob), [text("alice", b"after restart")]);
        provider.deliver(bob.send("alice", b"me too").unwrap());
        assert_eq!(provider.poll(&mut alice), [text("bob", b"me too")]);

        // Bob's invite for carol survived the restart.
        let mut carol = Messenger::new().unwrap();
        carol.accept_invite("bob", invite).unwrap();
        assert_eq!(provider.poll(&mut carol), [Event::Connected("bob".into())]);
        assert_eq!(provider.poll(&mut bob), [Event::Connected("carol".into())]);
    }

    #[test]
    fn snapshot_rejects_garbage() {
        let snapshot = Messenger::new().unwrap().to_snapshot().unwrap();
        assert!(Messenger::from_snapshot(&snapshot[..snapshot.len() - 1]).is_err());
        let mut wrong_version = snapshot.to_vec();
        wrong_version[0] = 99;
        assert!(Messenger::from_snapshot(&wrong_version).is_err());
        assert!(Messenger::from_snapshot(&[]).is_err());
    }

    #[test]
    fn rejects_duplicate_and_unsafe_names() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        assert!(bob.create_invite("alice").is_err());
        for bad in [
            "",
            "has space",
            "\u{1b}[2J",
            "ünïcode",
            &"x".repeat(MAX_NAME_CHARS + 1),
        ] {
            assert!(bob.create_invite(bad).is_err(), "{bad:?}");
        }
        assert!(alice.send("carol", b"x").is_err());
    }

    #[test]
    fn the_outbox_survives_a_restart_until_each_box_is_written() {
        let mut alice = Messenger::new().unwrap();
        let (_, bundle) = alice.create_invite("bob").unwrap();
        alice.keep_until_written(&bundle);
        let mut restored = Messenger::from_snapshot(&alice.to_snapshot().unwrap()).unwrap();
        let bytes = |writes: &[(BoxRef, Packet)]| {
            writes
                .iter()
                .map(|(at, packet)| (*at, packet.as_bytes().to_vec()))
                .collect::<Vec<_>>()
        };
        assert_eq!(bytes(restored.unwritten()), bytes(&bundle.writes));

        let first = bundle.writes.first().unwrap().0;
        assert!(restored.written(&first));
        assert!(!restored.written(&first), "already gone");
        assert_eq!(restored.unwritten().len(), bundle.writes.len() - 1);
        let again = Messenger::from_snapshot(&restored.to_snapshot().unwrap()).unwrap();
        assert_eq!(again.unwritten().len(), bundle.writes.len() - 1);
    }

    #[test]
    fn version_two_snapshots_still_load() {
        let alice = Messenger::new().unwrap();
        let mut old = alice.to_snapshot().unwrap().to_vec();
        // Version 2 is version 3 without the outbox count at the end.
        old[0] = 2;
        old.truncate(old.len() - 4);
        let restored = Messenger::from_snapshot(&old).unwrap();
        assert!(restored.unwritten().is_empty());
        old[0] = 4;
        assert!(Messenger::from_snapshot(&old).is_err());
    }
}
