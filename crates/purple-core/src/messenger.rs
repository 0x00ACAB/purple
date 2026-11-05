//! The messenger: contacts, invites and queues on top of [`Account`].
//!
//! It never touches the network. Callers ask which boxes to read next, hand it every
//! packet they find there, and write the boxes it returns.
//!
//! Connecting: the inviter writes a prekey bundle to the invite's bundle stream. The
//! accepter reads it, starts a session, and writes a hello to the invite's intro stream
//! carrying fresh secrets for both directions. From then on each direction is its own
//! stream of write-once boxes, read in order.
//!
//! Groups ride on those sessions: the creator asks a contact to join, the contact answers
//! with a key package, and the creator sends back the Welcome, all over 1:1. After that the
//! group's members share one stream per epoch (see [`crate::group`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use libsignal_protocol::IdentityKey;
use purple_ipc::{BoxRef, Packet, StreamSeed};
use zeroize::Zeroizing;

use crate::codec::{Reader, Writer};
use crate::content::Content;
use crate::fragment::{Reassembler, split};
use crate::group::{self, Group, GroupContent, MAX_MEMBERS, Received};
use crate::invite::{Invite, StoreRef};
use crate::mls::{Provider as Mls, SigningKey};
use crate::queue::{Queue, QueueSecret};
use crate::session::{Account, Error, Result};

/// Boxes to write.
#[derive(Debug, Default)]
pub struct Outgoing {
    /// Each box and the sealed packet that goes in it, in stream order.
    pub writes: Vec<(BoxRef, Packet)>,
}

/// What to do about a write that found its box already full. See [`Messenger::taken`].
#[derive(Debug)]
pub enum Taken {
    /// The box holds this user's own packet, written before: nothing to do but save.
    Ours,
    /// The box reads as empty: write this packet into it again.
    Resend(BoxRef, Packet),
    /// Someone else got there first: write these instead.
    Moved(Outgoing),
    /// Nothing is waiting on that box any more.
    Unknown,
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
    /// A contact asks this user to join a group.
    GroupRequest {
        /// The contact who created the group.
        creator: String,
        /// The group's name.
        group: String,
    },
    /// This user is now in a group.
    GroupJoined {
        /// The group's name.
        group: String,
        /// Who created it, or `None` if this user did.
        creator: Option<String>,
    },
    /// A member sent text to a group.
    GroupMessage {
        /// The group's name.
        group: String,
        /// Who sent it.
        from: GroupMember,
        /// Message text.
        body: Vec<u8>,
    },
    /// Something changed in a group: a member joined, left or was removed.
    GroupNotice {
        /// The group's name.
        group: String,
        /// What happened.
        text: String,
    },
    /// This user is no longer in a group.
    GroupLeft {
        /// The group's name.
        group: String,
        /// Why.
        reason: String,
    },
}

/// How a group member is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    /// Your name for them if they're your contact, otherwise the creator's name for them.
    pub name: String,
    /// Whether they're one of your contacts (or you).
    pub verified: bool,
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
    Group(String),
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
    /// Packets read ahead of their stream's next box, held until it's their turn.
    ahead: HashMap<StreamSeed, BTreeMap<u64, Packet>>,
    /// Packets handed to the network that it hasn't confirmed storing yet. Kept in the
    /// snapshot, so they're sent again after a restart.
    outbox: Vec<(BoxRef, Packet)>,
    /// OpenMLS state for every group.
    mls: Mls,
    groups: BTreeMap<String, Group>,
    /// Requests to join a group not answered yet: (creator, group).
    requests: BTreeSet<(String, String)>,
    /// Groups this user agreed to join, waiting for the creator's Welcome, with the signing
    /// key in the key package sent.
    joining: BTreeMap<(String, String), SigningKey>,
    /// The store this purple uses. Not saved: the launcher says on every start.
    store: StoreRef,
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
            ahead: HashMap::new(),
            outbox: Vec::new(),
            mls: Mls::new()?,
            groups: BTreeMap::new(),
            requests: BTreeSet::new(),
            joining: BTreeMap::new(),
            store: StoreRef::Memory,
        })
    }

    /// Use `store` for new invites, and accept only invites made on it.
    pub fn set_store(&mut self, store: StoreRef) {
        self.store = store;
    }

    /// Create an invite for a contact who will be known as `contact`. Returns the invite to
    /// show as a QR code or link, and the bundle boxes to write.
    ///
    /// # Errors
    /// Fails if `contact` is already in use, or generating the prekeys fails.
    pub fn create_invite(&mut self, contact: &str) -> Result<(Invite, Outgoing)> {
        self.check_name_free(contact)?;
        let (invite, bundle) = self.account.create_invite(self.store.clone())?;
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
    /// Fails if `contact` is already in use, or the invite is for another store.
    pub fn accept_invite(&mut self, contact: &str, invite: Invite) -> Result<()> {
        if invite.store() != Some(&self.store) {
            return Err(Error::WrongStore(
                invite
                    .store()
                    .map_or_else(|| "unknown".into(), StoreRef::describe),
            ));
        }
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

    /// The boxes to read: each stream's next box and, while the stream holds an incomplete
    /// message, up to [`READ_AHEAD`] boxes after it that aren't already held.
    ///
    /// # Errors
    /// Fails only if queue derivation fails.
    pub fn reads(&self) -> Result<Vec<BoxRef>> {
        let mut out = Vec::new();
        for (_, queue, next) in self.streams()? {
            let stream = queue.stream();
            out.push(BoxRef {
                stream,
                index: next,
            });
            let missing = self
                .reassemblers
                .get(&stream)
                .map_or(0, Reassembler::missing);
            let ahead = u64::try_from(missing).unwrap_or(u64::MAX).min(READ_AHEAD);
            let held = self.ahead.get(&stream);
            for step in 1..=ahead {
                let index = next
                    .checked_add(step)
                    .ok_or(Error::State("stream index exhausted"))?;
                if !held.is_some_and(|held| held.contains_key(&index)) {
                    out.push(BoxRef { stream, index });
                }
            }
        }
        Ok(out)
    }

    /// A packet read ahead that is now its stream's next box, to pass to [`Self::receive`].
    /// Call it after each `receive` until it returns `None`.
    ///
    /// # Errors
    /// Fails only if queue derivation fails.
    pub fn buffered_next(&mut self) -> Result<Option<(BoxRef, Packet)>> {
        let next: HashMap<StreamSeed, u64> = self
            .streams()?
            .into_iter()
            .map(|(_, queue, next)| (queue.stream(), next))
            .collect();
        self.ahead.retain(|stream, held| {
            let Some(&next) = next.get(stream) else {
                return false;
            };
            held.retain(|&index, _| index >= next);
            !held.is_empty()
        });
        for (stream, held) in &mut self.ahead {
            let Some(&index) = next.get(stream) else {
                continue;
            };
            if let Some(packet) = held.remove(&index) {
                return Ok(Some((
                    BoxRef {
                        stream: *stream,
                        index,
                    },
                    packet,
                )));
            }
        }
        Ok(None)
    }

    /// Handle the packet read from box `at`, which must be the next box of one of the
    /// streams in [`Self::reads`], or up to [`READ_AHEAD`] past it, in which case the packet
    /// is held until [`Self::buffered_next`] hands it back.
    ///
    /// The stream moves on to the next box even if this packet turns out to be forged or
    /// malformed, so one bad box can't block the stream.
    ///
    /// # Errors
    /// Fails if `at` isn't the next box of a stream this messenger reads, or the packet is
    /// forged, malformed or replayed.
    pub fn receive(&mut self, at: BoxRef, packet: &Packet) -> Result<Step> {
        let (route, queue, next) = self.route(at.stream)?;
        if at.index != next {
            let within = at
                .index
                .checked_sub(next)
                .is_some_and(|distance| (1..=READ_AHEAD).contains(&distance));
            if !within {
                return Err(Error::State("box read out of order"));
            }
            self.ahead
                .entry(at.stream)
                .or_default()
                .insert(at.index, packet.clone());
            return Ok(Step::default());
        }
        self.advance(&route, at.stream)?;
        if let Route::Group(name) = &route {
            let mine = match self.groups.get_mut(name) {
                Some(group) => group
                    .stream_mut(at.stream)?
                    .is_some_and(|stream| stream.read_back(at.index, packet)),
                None => false,
            };
            if mine {
                return Ok(Step::default());
            }
        }
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
            Route::Group(name) => self.deliver_group(&name, &message),
        }
    }

    /// Encrypt a text message for `contact`.
    ///
    /// # Errors
    /// Fails if `contact` isn't a connected contact.
    pub fn send(&mut self, contact: &str, body: &[u8]) -> Result<Outgoing> {
        self.send_content(contact, &Content::Text(body.to_vec()))
    }

    fn send_content(&mut self, contact: &str, content: &Content) -> Result<Outgoing> {
        let known = self
            .contacts
            .get(contact)
            .ok_or(Error::State("unknown contact"))?;
        let queue = known.send.queue()?;
        let first = known.next_send;
        let wire = self.account.encrypt(contact, &content.encode()?)?;
        let (out, next) = outgoing(&queue, first, &wire)?;
        if let Some(state) = self.contacts.get_mut(contact) {
            state.next_send = next;
        }
        Ok(out)
    }

    /// Create a group with this user as its only member.
    ///
    /// # Errors
    /// Fails if the name is invalid or in use.
    pub fn create_group(&mut self, group: &str) -> Result<()> {
        self.check_group_name_free(group)?;
        let created = Group::create(&self.mls, &self.account)?;
        self.groups.insert(group.to_owned(), created);
        Ok(())
    }

    /// Ask `contact` to join `group`, which this user created.
    ///
    /// # Errors
    /// Fails if this user isn't the creator, `contact` isn't a contact, is already in or
    /// asked, or the group is full.
    pub fn ask_to_join(&mut self, group: &str, contact: &str) -> Result<Outgoing> {
        let identity = self.contact_identity(contact)?;
        let state = self
            .groups
            .get(group)
            .ok_or(Error::State("no such group"))?;
        if state.creator().is_some() {
            return Err(Error::State("only the group's creator adds members"));
        }
        if state.identities()?.contains(&identity) {
            return Err(Error::State("already a member"));
        }
        if state.member_count().saturating_add(state.asked_count()) >= MAX_MEMBERS {
            return Err(Error::State("groups are capped at 50 members"));
        }
        let request = Content::GroupRequest {
            group: group.to_owned(),
        };
        let out = self.send_content(contact, &request)?;
        if let Some(asked) = self.groups.get_mut(group) {
            asked.ask(contact.to_owned());
        }
        Ok(out)
    }

    /// Accept `creator`'s request to join `group`.
    ///
    /// # Errors
    /// Fails if there's no such request or the group name is already used here.
    pub fn join_group(&mut self, creator: &str, group: &str) -> Result<Outgoing> {
        let request = (creator.to_owned(), group.to_owned());
        if !self.requests.contains(&request) {
            return Err(Error::State("no request to join that group"));
        }
        self.check_group_name_free(group)?;
        let (key, key_package) = group::key_package(&self.mls, &self.account)?;
        let accept = Content::GroupAccept {
            group: group.to_owned(),
            key_package,
        };
        let out = self.send_content(creator, &accept)?;
        self.requests.remove(&request);
        self.joining.insert(request, key);
        Ok(out)
    }

    /// Remove `member` (one of this user's contacts) from `group`, or cancel the request if
    /// they haven't answered. An empty result means a request was cancelled.
    ///
    /// # Errors
    /// Fails if this user isn't the creator or `member` isn't in the group.
    pub fn remove_from_group(&mut self, group: &str, member: &str) -> Result<Vec<Outgoing>> {
        let identity = self.account.peer_identity(member)?;
        let state = self
            .groups
            .get_mut(group)
            .ok_or(Error::State("no such group"))?;
        if state.creator().is_some() {
            return Err(Error::State("only the group's creator removes members"));
        }
        if state.cancel_ask(member) {
            return Ok(Vec::new());
        }
        let identity = identity.ok_or(Error::State("not a member of this group"))?;
        Ok(vec![state.remove(&self.mls, &identity)?])
    }

    /// Leave `group`: tell the creator (if it isn't this user) and forget the group.
    ///
    /// # Errors
    /// Fails if there's no such group, or this user created it and others are still in
    /// it: only the creator can change membership, so leaving would freeze the group for
    /// everyone, with no way to remove anyone again.
    pub fn leave_group(&mut self, group: &str) -> Result<Vec<Outgoing>> {
        let found = self
            .groups
            .get(group)
            .ok_or(Error::State("no such group"))?;
        if found.creator().is_none() && found.member_count() > 1 {
            return Err(Error::State(
                "you created this group: remove the other members first",
            ));
        }
        let state = self
            .groups
            .remove(group)
            .ok_or(Error::State("no such group"))?;
        let creator = state
            .creator()
            .filter(|creator| self.contacts.contains_key(*creator))
            .map(str::to_owned);
        let mut out = Vec::new();
        if let Some(creator) = creator {
            let leave = Content::GroupLeave {
                group: group.to_owned(),
            };
            out.push(self.send_content(&creator, &leave)?);
        }
        state.delete(&self.mls)?;
        Ok(out)
    }

    /// Send text to `group`.
    ///
    /// # Errors
    /// Fails if there's no such group.
    pub fn send_group(&mut self, group: &str, body: &[u8]) -> Result<Outgoing> {
        let state = self
            .groups
            .get_mut(group)
            .ok_or(Error::State("no such group"))?;
        state.send(&self.mls, &GroupContent::Text(body.to_vec()))
    }

    /// Who is in `group`, as this user sees them.
    ///
    /// # Errors
    /// Fails if there's no such group or a credential doesn't check out.
    pub fn group_members(&self, group: &str) -> Result<Vec<GroupMember>> {
        let state = self
            .groups
            .get(group)
            .ok_or(Error::State("no such group"))?;
        state
            .identities()?
            .iter()
            .map(|identity| self.display(state, identity))
            .collect()
    }

    /// Every group, with its creator (`None` for this user's own).
    #[must_use]
    pub fn groups(&self) -> Vec<(String, Option<String>)> {
        self.groups
            .iter()
            .map(|(name, group)| (name.clone(), group.creator().map(str::to_owned)))
            .collect()
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

    /// A write to box `at` was reported taken, and the box holds `found` (`None` if it read
    /// as empty). Says what to do with the packet kept for that box.
    ///
    /// In a group stream another member may have got there first; the packet is then
    /// resealed for the next free box ([`Taken::Moved`]).
    ///
    /// # Errors
    /// Fails if someone else's packet is in a box only this user writes, in which case the
    /// packet meant for it is dropped.
    pub fn taken(&mut self, at: &BoxRef, found: Option<&Packet>) -> Result<Taken> {
        let Some(position) = self.outbox.iter().position(|(kept, _)| kept == at) else {
            return Ok(Taken::Unknown);
        };
        let Some(found) = found else {
            let kept = self
                .outbox
                .get(position)
                .map(|(_, packet)| packet.clone())
                .ok_or(Error::State("outbox entry vanished"))?;
            // The store hasn't caught up with what it said is there; write it again.
            return Ok(Taken::Resend(*at, kept));
        };
        let (_, kept) = self.outbox.remove(position);
        if kept == *found {
            return Ok(Taken::Ours);
        }
        for group in self.groups.values_mut() {
            if let Some(stream) = group.stream_mut(at.stream)? {
                let (moved, packet) = stream.replace(at.index, &kept)?;
                return Ok(Taken::Moved(Outgoing {
                    writes: vec![(moved, packet)],
                }));
            }
        }
        Err(Error::State(
            "someone else wrote into a box only this user writes to; the message meant for it \
             was lost",
        ))
    }

    /// Box `at` read as empty at `now` (Unix seconds). Old group streams that have been
    /// quiet for [`group::DRAIN_SECS`] are dropped. Returns whether anything changed that
    /// should be saved.
    ///
    /// # Errors
    /// Fails only if queue derivation fails.
    pub fn empty(&mut self, at: &BoxRef, now: u64) -> Result<bool> {
        for group in self.groups.values_mut() {
            if group.note_empty(at, now)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Packets the network hasn't confirmed storing, oldest first.
    #[must_use]
    pub fn unwritten(&self) -> &[(BoxRef, Packet)] {
        &self.outbox
    }

    /// Serialize everything needed to resume: the account (identity, prekeys, sessions),
    /// contacts with their queue secrets and stream positions, pending invites, packets not
    /// yet confirmed stored, partly reassembled messages (so a restart in the middle of a
    /// long message doesn't lose it), and groups with their MLS state.
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
        let mut partial: Vec<_> = self
            .reassemblers
            .iter()
            .filter(|(_, reassembler)| reassembler.missing() > 0)
            .collect();
        partial.sort_by_key(|(stream, _)| **stream);
        w.len(partial.len())?;
        for (stream, reassembler) in partial {
            w.bytes(&stream.0)?;
            reassembler.encode(&mut w)?;
        }
        self.mls.encode(&mut w)?;
        w.len(self.groups.len())?;
        for (name, group) in &self.groups {
            w.bytes(name.as_bytes())?;
            group.encode(&mut w)?;
        }
        w.len(self.requests.len())?;
        for (creator, group) in &self.requests {
            w.bytes(creator.as_bytes())?;
            w.bytes(group.as_bytes())?;
        }
        w.len(self.joining.len())?;
        for ((creator, group), key) in &self.joining {
            w.bytes(creator.as_bytes())?;
            w.bytes(group.as_bytes())?;
            key.encode(&mut w)?;
        }
        Ok(w.finish())
    }

    /// Restore a messenger from [`Self::to_snapshot`], or from an older snapshot: version 4
    /// had no groups, version 3 also no partial messages, version 2 also no outbox.
    ///
    /// # Errors
    /// Fails on an unknown version or any malformed field.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if !(2..=SNAPSHOT_VERSION).contains(&version) {
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
        if version >= 3 {
            for _ in 0..r.len()? {
                let at = BoxRef {
                    stream: seed(r.bytes()?)?,
                    index: r.u64()?,
                };
                outbox.push((at, Packet::from_slice(r.bytes()?)?));
            }
        }
        let mut reassemblers = HashMap::new();
        if version >= 4 {
            for _ in 0..r.len()? {
                let stream = seed(r.bytes()?)?;
                reassemblers.insert(stream, Reassembler::decode(&mut r)?);
            }
        }
        let mut groups = BTreeMap::new();
        let mut requests = BTreeSet::new();
        let mut joining = BTreeMap::new();
        let mls = if version >= 5 {
            let mls = Mls::decode(&mut r)?;
            for _ in 0..r.len()? {
                let name = r.string()?;
                groups.insert(name, Group::decode(&mut r, &mls)?);
            }
            for _ in 0..r.len()? {
                requests.insert((r.string()?, r.string()?));
            }
            for _ in 0..r.len()? {
                let request = (r.string()?, r.string()?);
                joining.insert(request, SigningKey::decode(&mut r)?);
            }
            mls
        } else {
            Mls::new()?
        };
        r.finish()?;
        Ok(Self {
            account,
            contacts,
            invites,
            accepting,
            reassemblers,
            ahead: HashMap::new(),
            outbox,
            mls,
            groups,
            requests,
            joining,
            store: StoreRef::Memory,
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
        let wire = self.account.encrypt(name, &hello.encode()?)?;
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
            Content::GroupRequest { group } => self.on_group_request(name, group),
            Content::GroupAccept { group, key_package } => {
                self.on_group_accept(name, &group, &key_package)
            }
            Content::GroupWelcome {
                group,
                welcome,
                names,
            } => self.on_group_welcome(name, &group, &welcome, names),
            Content::GroupLeave { group } => self.on_group_leave(name, &group),
        }
    }

    /// The identity key of connected contact `contact`.
    fn contact_identity(&self, contact: &str) -> Result<IdentityKey> {
        if !self.contacts.contains_key(contact) {
            return Err(Error::State("unknown contact"));
        }
        self.account
            .peer_identity(contact)?
            .ok_or(Error::State("no identity key for that contact yet"))
    }

    fn creator_identity(&self, group: &Group) -> Result<IdentityKey> {
        group.creator().map_or_else(
            || Ok(self.account.identity_key()),
            |creator| self.contact_identity(creator),
        )
    }

    /// How `identity`, a member of `group`, is shown to this user. A member who is one of
    /// this user's contacts gets this user's name for them, whatever the creator said.
    fn display(&self, group: &Group, identity: &IdentityKey) -> Result<GroupMember> {
        if *identity == self.account.identity_key() {
            return Ok(GroupMember {
                name: "me".into(),
                verified: true,
            });
        }
        for name in self.contacts.keys() {
            if self.account.peer_identity(name)?.as_ref() == Some(identity) {
                return Ok(GroupMember {
                    name: name.clone(),
                    verified: true,
                });
            }
        }
        Ok(GroupMember {
            name: group.name_for(identity).unwrap_or("unknown").to_owned(),
            verified: false,
        })
    }

    /// This user's names for the members of `group` who are their contacts.
    fn roster(&self, group: &Group) -> Result<Vec<(Vec<u8>, String)>> {
        let mut out = Vec::new();
        for identity in group.identities()? {
            let shown = self.display(group, &identity)?;
            if shown.verified && identity != self.account.identity_key() {
                out.push((identity.serialize().to_vec(), shown.name));
            }
        }
        Ok(out)
    }

    fn check_group_name_free(&self, group: &str) -> Result<()> {
        if !valid_name(group) {
            return Err(Error::State(
                "group names are 1 to 32 characters: letters, digits, - and _",
            ));
        }
        if self.groups.contains_key(group) || self.joining.keys().any(|(_, g)| g == group) {
            return Err(Error::State("group name already in use"));
        }
        Ok(())
    }

    fn on_group_request(&mut self, creator: &str, group: String) -> Result<Step> {
        if !valid_name(&group) {
            return Err(Error::Malformed("group request with an invalid name"));
        }
        let already = self
            .groups
            .get(&group)
            .is_some_and(|g| g.creator() == Some(creator));
        if already || !self.requests.insert((creator.to_owned(), group.clone())) {
            return Ok(Step::default());
        }
        Ok(Step {
            events: vec![Event::GroupRequest {
                creator: creator.to_owned(),
                group,
            }],
            outgoing: Vec::new(),
        })
    }

    /// A contact accepted: add them if they were asked, otherwise ignore it.
    fn on_group_accept(&mut self, contact: &str, group: &str, key_package: &[u8]) -> Result<Step> {
        let identity = self.contact_identity(contact)?;
        let Some(state) = self.groups.get_mut(group) else {
            return Ok(Step::default());
        };
        if state.creator().is_some() || !state.cancel_ask(contact) {
            return Ok(Step::default());
        }
        // Check first: anything written to the group stream before a failure would leave a
        // box that is never filled, and every member reads the stream in order.
        let key_package = state.check_key_package(&self.mls, key_package, &identity)?;
        let mut outgoing = Vec::new();
        // Members learn the newcomer's name before the commit that adds them.
        if state.member_count() > 1 {
            let names = vec![(identity.serialize().to_vec(), contact.to_owned())];
            outgoing.push(state.send(&self.mls, &GroupContent::Names(names))?);
        }
        let (commit, welcome) = state.add_checked(&self.mls, key_package)?;
        outgoing.extend(commit);
        let added = self
            .groups
            .get(group)
            .ok_or(Error::State("group vanished"))?;
        let names = self.roster(added)?;
        let welcome = Content::GroupWelcome {
            group: group.to_owned(),
            welcome,
            names,
        };
        // The commit is merged and must go out whatever happens to the Welcome.
        let mut events = vec![Event::GroupNotice {
            group: group.to_owned(),
            text: format!("{contact} joined"),
        }];
        match self.send_content(contact, &welcome) {
            Ok(out) => outgoing.push(out),
            Err(err) => events.push(Event::GroupNotice {
                group: group.to_owned(),
                text: format!(
                    "couldn't send {contact} the Welcome ({err}); remove and add them again"
                ),
            }),
        }
        Ok(Step { events, outgoing })
    }

    fn on_group_welcome(
        &mut self,
        creator: &str,
        group: &str,
        welcome: &[u8],
        names: Vec<(Vec<u8>, String)>,
    ) -> Result<Step> {
        let Some(key) = self.joining.remove(&(creator.to_owned(), group.to_owned())) else {
            return Ok(Step::default());
        };
        let creator_identity = self.contact_identity(creator)?;
        let joined = Group::join(
            &self.mls,
            key,
            creator.to_owned(),
            &creator_identity,
            welcome,
            names,
        )?;
        self.groups.insert(group.to_owned(), joined);
        Ok(Step {
            events: vec![Event::GroupJoined {
                group: group.to_owned(),
                creator: Some(creator.to_owned()),
            }],
            outgoing: Vec::new(),
        })
    }

    fn on_group_leave(&mut self, contact: &str, group: &str) -> Result<Step> {
        let identity = self.contact_identity(contact)?;
        let Some(state) = self.groups.get_mut(group) else {
            return Ok(Step::default());
        };
        if state.creator().is_some() || !state.identities()?.contains(&identity) {
            return Ok(Step::default());
        }
        let commit = state.remove(&self.mls, &identity)?;
        Ok(Step {
            events: vec![Event::GroupNotice {
                group: group.to_owned(),
                text: format!("{contact} left"),
            }],
            outgoing: vec![commit],
        })
    }

    /// One whole MLS message from a group's streams.
    fn deliver_group(&mut self, name: &str, message: &[u8]) -> Result<Step> {
        let found = self
            .groups
            .get(name)
            .ok_or(Error::State("group vanished"))?;
        let creator = self.creator_identity(found)?;
        let creator_name = found.creator().unwrap_or("you").to_owned();
        let state = self
            .groups
            .get_mut(name)
            .ok_or(Error::State("group vanished"))?;
        let received = state.receive(&self.mls, message, &creator)?;
        let group = name.to_owned();
        let events = match received {
            Received::Text { from, body } => {
                let current = self
                    .groups
                    .get(name)
                    .ok_or(Error::State("group vanished"))?;
                vec![Event::GroupMessage {
                    group,
                    from: self.display(current, &from)?,
                    body,
                }]
            }
            Received::Names(names) => {
                state.learn_names(names);
                Vec::new()
            }
            Received::Membership { added, removed } => {
                let current = self
                    .groups
                    .get(name)
                    .ok_or(Error::State("group vanished"))?;
                let mut events = Vec::new();
                for (ids, what) in [(added, "joined"), (removed, "was removed")] {
                    for id in ids {
                        let who = self.display(current, &id)?.name;
                        events.push(Event::GroupNotice {
                            group: group.clone(),
                            text: format!("{who} {what}"),
                        });
                    }
                }
                events
            }
            Received::Removed => {
                self.drop_group(name)?;
                vec![Event::GroupLeft {
                    group,
                    reason: format!("removed by {creator_name}"),
                }]
            }
            Received::Forged => {
                self.drop_group(name)?;
                vec![Event::GroupLeft {
                    group,
                    reason: format!(
                        "{creator_name} added a member with a forged credential, so you left"
                    ),
                }]
            }
            Received::Nothing => Vec::new(),
        };
        Ok(Step {
            events,
            outgoing: Vec::new(),
        })
    }

    fn drop_group(&mut self, name: &str) -> Result<()> {
        match self.groups.remove(name) {
            Some(group) => group.delete(&self.mls),
            None => Ok(()),
        }
    }

    /// Every stream this messenger reads, with how to route it, its queue and its next box.
    fn streams(&self) -> Result<Vec<(Route, Queue, u64)>> {
        let mut out = Vec::new();
        for (name, pending) in &self.accepting {
            out.push((
                Route::Bundle(name.clone()),
                pending.invite.bundle_queue()?,
                pending.next_read,
            ));
        }
        for (name, pending) in &self.invites {
            out.push((
                Route::Intro(name.clone()),
                pending.invite.intro_queue()?,
                pending.next_read,
            ));
        }
        for (name, contact) in &self.contacts {
            out.push((
                Route::Contact(name.clone()),
                contact.receive.queue()?,
                contact.next_read,
            ));
        }
        for (name, group) in &self.groups {
            for stream in group.streams() {
                out.push((
                    Route::Group(name.clone()),
                    stream.queue()?,
                    stream.next_read,
                ));
            }
        }
        Ok(out)
    }

    /// Find which stream `stream` is, with its queue and next box.
    fn route(&self, stream: StreamSeed) -> Result<(Route, Queue, u64)> {
        self.streams()?
            .into_iter()
            .find(|(_, queue, _)| queue.stream() == stream)
            .ok_or(Error::State(
                "packet for a stream this messenger doesn't read",
            ))
    }

    fn advance(&mut self, route: &Route, stream: StreamSeed) -> Result<()> {
        let next_read = match route {
            Route::Group(name) => {
                return self
                    .groups
                    .get_mut(name)
                    .ok_or(Error::State("stream vanished"))?
                    .stream_mut(stream)?
                    .ok_or(Error::State("stream vanished"))?
                    .advance();
            }
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

/// While a stream holds an incomplete message, boxes this far past its next one are read
/// at the same time. A 45-box commit then takes about three reads' time on Namenlos
/// instead of 45.
pub const READ_AHEAD: u64 = 16;

const SNAPSHOT_VERSION: u8 = 5;

fn secret(bytes: &[u8]) -> Result<QueueSecret> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Malformed("queue secret has the wrong length"))?;
    Ok(QueueSecret::from_bytes(Zeroizing::new(array)))
}

fn seed(bytes: &[u8]) -> Result<StreamSeed> {
    Ok(StreamSeed(bytes.try_into().map_err(|_| {
        Error::Malformed("stream seed has the wrong length")
    })?))
}

fn read_pending(r: &mut Reader<'_>) -> Result<BTreeMap<String, Pending>> {
    let mut out = BTreeMap::new();
    for _ in 0..r.len()? {
        let name = r.string()?;
        let pending = Pending {
            invite: Invite::decode_stored(r.bytes()?)?,
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
pub(crate) fn outgoing(queue: &Queue, first: u64, message: &[u8]) -> Result<(Outgoing, u64)> {
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

        /// Like `poll`, but a packet the messenger rejects is counted, not fatal.
        fn poll_counting_errors(&mut self, m: &mut Messenger) -> (Vec<Event>, usize) {
            let (mut events, mut errors) = (Vec::new(), 0_usize);
            loop {
                let mut progressed = false;
                for at in m.reads().unwrap() {
                    let Some(packet) = self.0.get(&at).cloned() else {
                        continue;
                    };
                    progressed = true;
                    match m.receive(at, &packet) {
                        Ok(step) => {
                            events.extend(step.events);
                            for out in step.outgoing {
                                self.deliver(out);
                            }
                        }
                        Err(_) => errors = errors.saturating_add(1),
                    }
                }
                if !progressed {
                    return (events, errors);
                }
            }
        }

        /// Write `out` the way purple-net would: keep it until written, report taken
        /// boxes, and write again wherever the messenger moves a packet.
        fn send(&mut self, m: &mut Messenger, out: Outgoing) {
            m.keep_until_written(&out);
            for (at, packet) in out.writes {
                if let Some(found) = self.0.get(&at).cloned() {
                    match m.taken(&at, Some(&found)).unwrap() {
                        Taken::Moved(moved) => self.send(m, moved),
                        Taken::Ours | Taken::Unknown => {}
                        Taken::Resend(..) => panic!("the box isn't empty"),
                    }
                } else {
                    self.0.insert(at, packet);
                    m.written(&at);
                }
            }
        }

        /// Read every stream `m` follows until nothing new turns up, writing what it sends.
        /// Boxes are offered in the order `reads` lists them, so boxes read ahead are held
        /// and then handed back through `buffered_next`.
        fn poll(&mut self, m: &mut Messenger) -> Vec<Event> {
            let mut events = Vec::new();
            loop {
                let mut progressed = false;
                for at in m.reads().unwrap() {
                    let Some(packet) = self.0.get(&at).cloned() else {
                        continue;
                    };
                    if !m.reads().unwrap().contains(&at) {
                        continue;
                    }
                    progressed = true;
                    let mut next = Some((at, packet));
                    while let Some((box_at, box_packet)) = next {
                        let step = m.receive(box_at, &box_packet).unwrap();
                        events.extend(step.events);
                        for out in step.outgoing {
                            self.deliver(out);
                        }
                        next = m.buffered_next().unwrap();
                    }
                }
                if !progressed {
                    return events;
                }
            }
        }
    }

    #[test]
    fn accepting_an_invite_for_another_store_is_refused() {
        let (mut alice, mut bob) = (Messenger::new().unwrap(), Messenger::new().unwrap());
        alice.set_store(StoreRef::Onion("a".repeat(56) + ".onion"));
        bob.set_store(StoreRef::Onion("b".repeat(56) + ".onion"));
        let (invite, _) = alice.create_invite("bob").unwrap();
        let err = bob
            .accept_invite("alice", Invite::decode(&invite.encode()).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("another store"), "{err}");
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
        // A box just past the next one is held for later, not delivered; one past the
        // read-ahead window is refused.
        let skipped = BoxRef {
            index: at.index + 1,
            ..at
        };
        assert!(bob.receive(skipped, &packet).unwrap().events.is_empty());
        let beyond = BoxRef {
            index: at.index + READ_AHEAD + 1,
            ..at
        };
        assert!(bob.receive(beyond, &packet).is_err());
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
        let (_, mallory_bundle) = Account::generate()
            .unwrap()
            .create_invite(StoreRef::Memory)
            .unwrap();
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
    fn older_snapshots_still_load() {
        let alice = Messenger::new().unwrap();
        let current = alice.to_snapshot().unwrap().to_vec();
        // Each older version lacks counts at the end: version 4 the four group counts
        // (MLS storage, groups, requests, joins), version 3 also the partial messages,
        // version 2 also the outbox.
        for (version, cut) in [(4, 16), (3, 20), (2, 24)] {
            let mut old = current.clone();
            old[0] = version;
            old.truncate(old.len() - cut);
            let restored = Messenger::from_snapshot(&old).unwrap();
            assert!(restored.unwritten().is_empty());
        }
        let mut future = current;
        future[0] = SNAPSHOT_VERSION + 1;
        assert!(Messenger::from_snapshot(&future).is_err());
    }

    #[test]
    fn long_messages_are_read_ahead_and_put_back_in_order() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let long = vec![b'y'; 5 * crate::fragment::FRAGMENT_DATA_LEN];
        let out = alice.send("bob", &long).unwrap();
        let first = out.writes[0].0;
        provider.deliver(out);

        // Reading the first box shows a message is incomplete: the next boxes are wanted
        // too, without waiting for each in turn.
        let packet = provider.0[&first].clone();
        bob.receive(first, &packet).unwrap();
        let wanted = bob.reads().unwrap();
        for ahead in 1..=4 {
            assert!(wanted.contains(&BoxRef {
                index: first.index + ahead,
                ..first
            }));
        }

        // Boxes arriving out of order are held until their turn.
        let last = BoxRef {
            index: first.index + 4,
            ..first
        };
        let held = provider.0[&last].clone();
        assert!(bob.receive(last, &held).unwrap().events.is_empty());
        assert!(bob.buffered_next().unwrap().is_none());
        assert_eq!(provider.poll(&mut bob), [text("alice", &long)]);
    }

    #[test]
    fn boxes_far_past_the_next_one_are_still_refused() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let (at, packet) = alice.send("bob", b"x").unwrap().writes[0].clone();
        let far = BoxRef {
            index: at.index + READ_AHEAD + 1,
            ..at
        };
        assert!(bob.receive(far, &packet).is_err());
    }

    #[test]
    fn a_half_read_message_survives_a_restart() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let long = vec![b'z'; 3 * crate::fragment::FRAGMENT_DATA_LEN];
        let out = alice.send("bob", &long).unwrap();
        let (first, packet) = out.writes[0].clone();
        provider.deliver(out);
        bob.receive(first, &packet).unwrap();

        let mut bob = Messenger::from_snapshot(&bob.to_snapshot().unwrap()).unwrap();
        assert_eq!(provider.poll(&mut bob), [text("alice", &long)]);
    }

    #[test]
    fn a_taken_box_holding_our_own_packet_counts_as_written() {
        let mut provider = Provider::default();
        let (mut alice, _bob) = connected(&mut provider);
        let out = alice.send("bob", b"x").unwrap();
        alice.keep_until_written(&out);
        let (at, packet) = out.writes[0].clone();
        assert!(matches!(
            alice.taken(&at, Some(&packet)).unwrap(),
            Taken::Ours
        ));
        assert_eq!(alice.unwritten().len(), out.writes.len() - 1);
        assert!(matches!(
            alice.taken(&at, Some(&packet)).unwrap(),
            Taken::Unknown
        ));
    }

    #[test]
    fn a_taken_box_that_reads_empty_is_written_again() {
        let mut provider = Provider::default();
        let (mut alice, _bob) = connected(&mut provider);
        let out = alice.send("bob", b"x").unwrap();
        alice.keep_until_written(&out);
        let (at, packet) = out.writes[0].clone();
        let Taken::Resend(again, same) = alice.taken(&at, None).unwrap() else {
            panic!("expected a resend");
        };
        assert_eq!((again, same), (at, packet));
        assert_eq!(
            alice.unwritten().len(),
            out.writes.len(),
            "still kept until written"
        );
    }

    #[test]
    fn someone_elses_packet_in_a_one_to_one_box_is_an_error() {
        let mut provider = Provider::default();
        let (mut alice, _bob) = connected(&mut provider);
        let out = alice.send("bob", b"x").unwrap();
        alice.keep_until_written(&out);
        let at = out.writes[0].0;
        let other = Packet::from_slice(&[0; purple_ipc::PACKET_LEN]).unwrap();
        assert!(alice.taken(&at, Some(&other)).is_err());
        assert_eq!(alice.unwritten().len(), out.writes.len() - 1);
    }

    /// Bob invites Alice, Carol invites Alice: Alice ends up with contacts "bob" and
    /// "carol"; Bob and Carol aren't each other's contacts.
    fn three(provider: &mut Provider) -> (Messenger, Messenger, Messenger) {
        let (mut alice, bob) = connected(provider);
        let mut carol = Messenger::new().unwrap();
        let (invite, bundle) = carol.create_invite("alice").unwrap();
        provider.deliver(bundle);
        alice.accept_invite("carol", invite).unwrap();
        assert_eq!(
            provider.poll(&mut alice),
            [Event::Connected("carol".into())]
        );
        assert_eq!(
            provider.poll(&mut carol),
            [Event::Connected("alice".into())]
        );
        (alice, bob, carol)
    }

    fn joined(group: &str, creator: &str) -> Event {
        Event::GroupJoined {
            group: group.into(),
            creator: Some(creator.into()),
        }
    }

    fn notice(group: &str, text: &str) -> Event {
        Event::GroupNotice {
            group: group.into(),
            text: text.into(),
        }
    }

    fn said(group: &str, from: &str, verified: bool, body: &[u8]) -> Event {
        Event::GroupMessage {
            group: group.into(),
            from: GroupMember {
                name: from.into(),
                verified,
            },
            body: body.to_vec(),
        }
    }

    /// Alice adds `name` to "team", and they accept.
    fn add(provider: &mut Provider, alice: &mut Messenger, name: &str, member: &mut Messenger) {
        provider.deliver(alice.ask_to_join("team", name).unwrap());
        assert_eq!(
            provider.poll(member),
            [Event::GroupRequest {
                creator: "alice".into(),
                group: "team".into()
            }]
        );
        provider.deliver(member.join_group("alice", "team").unwrap());
        assert_eq!(
            provider.poll(alice),
            [notice("team", &format!("{name} joined"))]
        );
        assert_eq!(provider.poll(member), [joined("team", "alice")]);
    }

    fn team(provider: &mut Provider) -> (Messenger, Messenger, Messenger) {
        let (mut alice, mut bob, mut carol) = three(provider);
        alice.create_group("team").unwrap();
        add(provider, &mut alice, "bob", &mut bob);
        add(provider, &mut alice, "carol", &mut carol);
        assert_eq!(provider.poll(&mut bob), [notice("team", "carol joined")]);
        (alice, bob, carol)
    }

    #[test]
    fn a_group_of_three_talks_and_names_members_by_who_knows_whom() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, mut carol) = team(&mut provider);
        provider.deliver(bob.send_group("team", b"hi all").unwrap());
        assert_eq!(
            provider.poll(&mut alice),
            [said("team", "bob", true, b"hi all")]
        );
        // Carol doesn't know Bob: she sees Alice's name for him, unverified.
        assert_eq!(
            provider.poll(&mut carol),
            [said("team", "bob", false, b"hi all")]
        );
        assert!(
            provider.poll(&mut bob).is_empty(),
            "his own message is skipped"
        );

        let members = carol.group_members("team").unwrap();
        for (name, verified) in [("alice", true), ("bob", false), ("me", true)] {
            let member = GroupMember {
                name: name.into(),
                verified,
            };
            assert!(members.contains(&member), "{members:?}");
        }
    }

    #[test]
    fn removal_and_leaving() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, mut carol) = team(&mut provider);
        for out in alice.remove_from_group("team", "carol").unwrap() {
            provider.deliver(out);
        }
        assert_eq!(
            provider.poll(&mut carol),
            [Event::GroupLeft {
                group: "team".into(),
                reason: "removed by alice".into()
            }]
        );
        assert_eq!(
            provider.poll(&mut bob),
            [notice("team", "carol was removed")]
        );
        assert!(carol.send_group("team", b"x").is_err());

        for out in bob.leave_group("team").unwrap() {
            provider.deliver(out);
        }
        assert_eq!(provider.poll(&mut alice), [notice("team", "bob left")]);
        assert_eq!(alice.group_members("team").unwrap().len(), 1);
    }

    #[test]
    fn removing_someone_who_hasnt_answered_cancels_the_request() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = three(&mut provider);
        alice.create_group("team").unwrap();
        provider.deliver(alice.ask_to_join("team", "bob").unwrap());
        provider.poll(&mut bob);
        assert!(alice.remove_from_group("team", "bob").unwrap().is_empty());
        // Bob's late acceptance adds nobody.
        provider.deliver(bob.join_group("alice", "team").unwrap());
        assert!(provider.poll(&mut alice).is_empty());
        assert_eq!(alice.group_members("team").unwrap().len(), 1);
    }

    #[test]
    fn an_accept_nobody_asked_for_adds_nobody() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = three(&mut provider);
        alice.create_group("team").unwrap();
        // Bob makes up a request on his side and sends a key package anyway.
        bob.requests.insert(("alice".into(), "team".into()));
        provider.deliver(bob.join_group("alice", "team").unwrap());
        assert!(provider.poll(&mut alice).is_empty());
        assert_eq!(alice.group_members("team").unwrap().len(), 1);
    }

    #[test]
    fn joining_under_a_name_already_used_fails_and_keeps_the_request() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = three(&mut provider);
        alice.create_group("team").unwrap();
        bob.create_group("team").unwrap();
        provider.deliver(alice.ask_to_join("team", "bob").unwrap());
        provider.poll(&mut bob);
        assert!(bob.join_group("alice", "team").is_err());
        bob.leave_group("team").unwrap();
        assert!(bob.join_group("alice", "team").is_ok());
    }

    #[test]
    fn only_the_creator_adds_and_strangers_cant_be_added() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = team(&mut provider);
        assert!(bob.ask_to_join("team", "alice").is_err());
        assert!(alice.ask_to_join("team", "nobody").is_err());
        assert!(
            alice.ask_to_join("team", "bob").is_err(),
            "already a member"
        );
    }

    #[test]
    fn groups_survive_a_restart() {
        let mut provider = Provider::default();
        let (alice, bob, carol) = team(&mut provider);
        let mut alice = Messenger::from_snapshot(&alice.to_snapshot().unwrap()).unwrap();
        let mut bob = Messenger::from_snapshot(&bob.to_snapshot().unwrap()).unwrap();
        let mut carol = Messenger::from_snapshot(&carol.to_snapshot().unwrap()).unwrap();
        assert_eq!(alice.groups(), [("team".to_owned(), None)]);
        provider.deliver(carol.send_group("team", b"still here").unwrap());
        assert_eq!(
            provider.poll(&mut alice),
            [said("team", "carol", true, b"still here")]
        );
        assert_eq!(
            provider.poll(&mut bob),
            [said("team", "carol", false, b"still here")]
        );
    }

    #[test]
    fn two_members_writing_the_same_box_both_get_through_in_one_order() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, mut carol) = team(&mut provider);
        let from_bob = bob.send_group("team", b"from bob").unwrap();
        let from_carol = carol.send_group("team", b"from carol").unwrap();
        assert_eq!(
            from_bob.writes[0].0, from_carol.writes[0].0,
            "both chose the same box"
        );
        provider.send(&mut bob, from_bob);
        provider.send(&mut carol, from_carol);
        assert_eq!(
            provider.poll(&mut alice),
            [
                said("team", "bob", true, b"from bob"),
                said("team", "carol", true, b"from carol")
            ]
        );
        assert_eq!(
            provider.poll(&mut bob),
            [said("team", "carol", false, b"from carol")]
        );
        assert_eq!(
            provider.poll(&mut carol),
            [said("team", "bob", false, b"from bob")]
        );
    }

    #[test]
    fn an_own_write_found_after_a_restart_is_not_moved() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = team(&mut provider);
        let out = bob.send_group("team", b"once").unwrap();
        bob.keep_until_written(&out);
        let (at, packet) = out.writes[0].clone();
        // It landed, but the answer was lost.
        provider.0.insert(at, packet.clone());
        let mut bob = Messenger::from_snapshot(&bob.to_snapshot().unwrap()).unwrap();
        assert!(matches!(
            bob.taken(&at, Some(&packet)).unwrap(),
            Taken::Ours
        ));
        assert_eq!(
            provider.poll(&mut alice),
            [said("team", "bob", true, b"once")]
        );
        assert!(provider.poll(&mut bob).is_empty());
    }

    #[test]
    fn old_streams_are_read_until_quiet_then_dropped() {
        let mut provider = Provider::default();
        let (mut alice, _bob, mut carol) = team(&mut provider);
        // Carol writes in the epoch that Alice's removal of Bob is about to end.
        let late = carol.send_group("team", b"late").unwrap();
        for out in alice.remove_from_group("team", "bob").unwrap() {
            provider.send(&mut alice, out);
        }
        provider.send(&mut carol, late);
        let events = provider.poll(&mut alice);
        assert!(
            events.contains(&said("team", "carol", true, b"late")),
            "{events:?}"
        );

        // Alice reads her two 1:1 streams, the current epoch's stream and the two before
        // it. Only the old epochs go once they've been quiet long enough.
        let before = alice.reads().unwrap();
        let start = 1_000;
        for at in &before {
            assert!(!alice.empty(at, start).unwrap());
            assert!(!alice.empty(at, start + group::DRAIN_SECS - 1).unwrap());
        }
        let dropped = before
            .iter()
            .filter(|at| alice.empty(at, start + group::DRAIN_SECS).unwrap())
            .count();
        assert_eq!(dropped, 2, "the two old epochs, nothing else");
        assert_eq!(alice.reads().unwrap().len(), before.len() - 2);
    }

    #[test]
    fn a_half_read_group_message_survives_a_restart() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, _carol) = team(&mut provider);
        let long = vec![b'q'; 3 * crate::fragment::FRAGMENT_DATA_LEN];
        let out = alice.send_group("team", &long).unwrap();
        assert!(out.writes.len() > 1);
        let (first, packet) = out.writes[0].clone();
        provider.send(&mut alice, out);
        bob.receive(first, &packet).unwrap();
        let mut bob = Messenger::from_snapshot(&bob.to_snapshot().unwrap()).unwrap();
        assert_eq!(
            provider.poll(&mut bob),
            [said("team", "alice", true, &long)]
        );
    }

    #[test]
    fn a_bad_key_package_leaves_no_hole_in_the_group_stream() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, mut carol) = three(&mut provider);
        alice.create_group("team").unwrap();
        add(&mut provider, &mut alice, "bob", &mut bob);
        provider.deliver(alice.ask_to_join("team", "carol").unwrap());
        provider.poll(&mut carol);
        let garbage = Content::GroupAccept {
            group: "team".into(),
            key_package: vec![1, 2, 3],
        };
        provider.deliver(carol.send_content("alice", &garbage).unwrap());
        let (_, errors) = provider.poll_counting_errors(&mut alice);
        assert_eq!(errors, 1);
        provider.deliver(alice.send_group("team", b"still flowing").unwrap());
        assert_eq!(
            provider.poll(&mut bob),
            [said("team", "alice", true, b"still flowing")]
        );
    }

    #[test]
    fn a_stream_with_own_writes_in_flight_is_kept_until_they_settle() {
        let mut provider = Provider::default();
        let (mut alice, mut bob, mut carol) = team(&mut provider);
        // Carol's packet lands in the box Bob also chose; Bob's Taken report is slow.
        let from_bob = bob.send_group("team", b"from bob").unwrap();
        bob.keep_until_written(&from_bob);
        let (at, _) = from_bob.writes[0].clone();
        let from_carol = carol.send_group("team", b"from carol").unwrap();
        provider.send(&mut carol, from_carol);
        // Meanwhile Alice removes Carol, Bob moves on, and the old stream goes quiet.
        for out in alice.remove_from_group("team", "carol").unwrap() {
            provider.send(&mut alice, out);
        }
        provider.poll(&mut bob);
        let reading = bob.reads().unwrap();
        for next in &reading {
            bob.empty(next, 1_000).unwrap();
        }
        for next in &reading {
            let dropped = bob.empty(next, 1_000 + group::DRAIN_SECS).unwrap();
            assert!(
                !dropped || next.stream != at.stream,
                "kept: Bob's write is pending"
            );
        }
        // When the report comes, Bob's packet moves on in the same stream.
        let found = provider.0[&at].clone();
        let Taken::Moved(moved) = bob.taken(&at, Some(&found)).unwrap() else {
            panic!("expected the packet to move");
        };
        assert_eq!(moved.writes[0].0.stream, at.stream);
    }

    #[test]
    fn the_creator_cant_walk_away_from_a_group_with_members() {
        let mut provider = Provider::default();
        let (mut alice, _bob, _carol) = team(&mut provider);
        assert!(alice.leave_group("team").is_err());
        assert_eq!(alice.group_members("team").unwrap().len(), 3);
        for member in ["bob", "carol"] {
            for out in alice.remove_from_group("team", member).unwrap() {
                provider.send(&mut alice, out);
            }
        }
        assert!(alice.leave_group("team").unwrap().is_empty());
        assert!(alice.groups().is_empty());
    }
}
