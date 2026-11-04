//! The messenger: contacts, invites and queues on top of [`Account`].
//!
//! It never touches the network. Callers ask which mailboxes to poll, hand it every packet
//! fetched from them, and deliver the packets it returns.
//!
//! Connecting: the inviter stores a prekey bundle in the invite's bundle queue. The
//! accepter fetches it, starts a session, and sends a hello to the invite's intro queue
//! carrying fresh secrets for both directions. From then on each direction uses its own
//! queue, whose mailbox and key change every epoch.

use std::collections::{BTreeMap, HashMap};

use purple_ipc::{MailboxId, Packet};

use crate::content::Content;
use crate::fragment::{Reassembler, split};
use crate::invite::Invite;
use crate::queue::{Queue, QueueSecret, epoch};
use crate::session::{Account, Error, Result};

/// Packets to deliver to one mailbox.
#[derive(Debug)]
pub struct Outgoing {
    /// Destination mailbox.
    pub mailbox: MailboxId,
    /// Sealed packets, in order.
    pub packets: Vec<Packet>,
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
    /// Packets to deliver.
    pub outgoing: Vec<Outgoing>,
}

struct Contact {
    send: QueueSecret,
    receive: QueueSecret,
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
    /// Invites this user created, waiting for the accepter's hello.
    invites: BTreeMap<String, Invite>,
    /// Invites this user accepted, waiting for the inviter's bundle.
    accepting: BTreeMap<String, Invite>,
    reassemblers: HashMap<MailboxId, Reassembler>,
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
        })
    }

    /// Create an invite for a contact who will be known as `contact`. Returns the invite to
    /// show as a QR code or link, and the bundle packets to deliver.
    ///
    /// # Errors
    /// Fails if `contact` is already in use, or generating the prekeys fails.
    pub fn create_invite(&mut self, contact: &str) -> Result<(Invite, Outgoing)> {
        self.check_name_free(contact)?;
        let (invite, bundle) = self.account.create_invite()?;
        let outgoing = outgoing(&invite.bundle_queue()?, &bundle)?;
        self.invites.insert(contact.to_owned(), invite.clone());
        Ok((invite, outgoing))
    }

    /// Accept a scanned invite from a contact who will be known as `contact`. The session
    /// starts once the inviter's bundle arrives through [`Self::receive`].
    ///
    /// # Errors
    /// Fails if `contact` is already in use.
    pub fn accept_invite(&mut self, contact: &str, invite: Invite) -> Result<()> {
        self.check_name_free(contact)?;
        self.accepting.insert(contact.to_owned(), invite);
        Ok(())
    }

    /// Every mailbox to poll at time `now` (Unix seconds). For each contact that's the
    /// receive queue for the current epoch and the ones either side, to tolerate clock skew
    /// between the two devices.
    ///
    /// # Errors
    /// Fails only if queue derivation fails.
    pub fn mailboxes(&self, now: u64) -> Result<Vec<MailboxId>> {
        let mut out = Vec::new();
        for invite in self.accepting.values() {
            out.push(invite.bundle_queue()?.mailbox());
        }
        for invite in self.invites.values() {
            out.push(invite.intro_queue()?.mailbox());
        }
        for contact in self.contacts.values() {
            for e in epochs_around(now) {
                out.push(contact.receive.queue(e)?.mailbox());
            }
        }
        Ok(out)
    }

    /// Handle one packet fetched from `mailbox`.
    ///
    /// # Errors
    /// Fails if the mailbox isn't one this messenger polls, or the packet is forged,
    /// malformed or replayed. The messenger's state is unchanged on failure.
    pub fn receive(&mut self, mailbox: MailboxId, packet: &Packet, now: u64) -> Result<Step> {
        let (route, queue) = self.route(mailbox, now)?;
        let fragment = queue.open(packet)?;
        let Some(message) = self
            .reassemblers
            .entry(mailbox)
            .or_default()
            .push(&fragment)?
        else {
            return Ok(Step::default());
        };
        match route {
            Route::Bundle(name) => self.finish_accept(&name, mailbox, &message),
            Route::Intro(name) => self.finish_invite(&name, mailbox, &message),
            Route::Contact(name) => self.deliver(&name, &message),
        }
    }

    /// Encrypt a text message for `contact`.
    ///
    /// # Errors
    /// Fails if `contact` isn't a connected contact.
    pub fn send(&mut self, contact: &str, body: &[u8], now: u64) -> Result<Outgoing> {
        let queue = self
            .contacts
            .get(contact)
            .ok_or(Error::State("unknown contact"))?
            .send
            .queue(epoch(now))?;
        let wire = self
            .account
            .encrypt(contact, &Content::Text(body.to_vec()).encode())?;
        outgoing(&queue, &wire)
    }

    /// Names of connected contacts.
    pub fn contacts(&self) -> impl Iterator<Item = &str> {
        self.contacts.keys().map(String::as_str)
    }

    fn finish_accept(&mut self, name: &str, mailbox: MailboxId, bundle: &[u8]) -> Result<Step> {
        let invite = self
            .accepting
            .get(name)
            .ok_or(Error::State("no pending accept"))?
            .clone();
        // A bundle that fails here (for example one planted by someone else who saw the QR
        // code) leaves the accept pending, so the real bundle can still complete it.
        self.account.accept_invite(name, &invite, bundle)?;

        let to_inviter = QueueSecret::random()?;
        let to_accepter = QueueSecret::random()?;
        let hello = Content::Hello {
            to_inviter: to_inviter.clone(),
            to_accepter: to_accepter.clone(),
        };
        let wire = self.account.encrypt(name, &hello.encode())?;
        let intro = outgoing(&invite.intro_queue()?, &wire)?;

        self.accepting.remove(name);
        self.reassemblers.remove(&mailbox);
        self.contacts.insert(
            name.to_owned(),
            Contact {
                send: to_inviter,
                receive: to_accepter,
            },
        );
        Ok(Step {
            events: vec![Event::Connected(name.to_owned())],
            outgoing: vec![intro],
        })
    }

    fn finish_invite(&mut self, name: &str, mailbox: MailboxId, wire: &[u8]) -> Result<Step> {
        let Content::Hello {
            to_inviter,
            to_accepter,
        } = Content::decode(&self.account.decrypt(name, wire)?)?
        else {
            return Err(Error::Malformed("expected a hello on the intro queue"));
        };
        self.invites.remove(name);
        self.reassemblers.remove(&mailbox);
        self.contacts.insert(
            name.to_owned(),
            Contact {
                send: to_accepter,
                receive: to_inviter,
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

    fn route(&self, mailbox: MailboxId, now: u64) -> Result<(Route, Queue)> {
        for (name, invite) in &self.accepting {
            let queue = invite.bundle_queue()?;
            if queue.mailbox() == mailbox {
                return Ok((Route::Bundle(name.clone()), queue));
            }
        }
        for (name, invite) in &self.invites {
            let queue = invite.intro_queue()?;
            if queue.mailbox() == mailbox {
                return Ok((Route::Intro(name.clone()), queue));
            }
        }
        for (name, contact) in &self.contacts {
            for e in epochs_around(now) {
                let queue = contact.receive.queue(e)?;
                if queue.mailbox() == mailbox {
                    return Ok((Route::Contact(name.clone()), queue));
                }
            }
        }
        Err(Error::State(
            "packet for a mailbox this messenger doesn't poll",
        ))
    }

    fn check_name_free(&self, name: &str) -> Result<()> {
        if self.contacts.contains_key(name)
            || self.invites.contains_key(name)
            || self.accepting.contains_key(name)
        {
            return Err(Error::State("contact name already in use"));
        }
        Ok(())
    }
}

/// The previous, current and next epoch at `now`.
fn epochs_around(now: u64) -> impl Iterator<Item = u64> {
    let e = epoch(now);
    [e.checked_sub(1), Some(e), e.checked_add(1)]
        .into_iter()
        .flatten()
}

fn outgoing(queue: &Queue, message: &[u8]) -> Result<Outgoing> {
    let packets = split(message)?
        .iter()
        .map(|fragment| queue.seal(fragment))
        .collect::<Result<_>>()?;
    Ok(Outgoing {
        mailbox: queue.mailbox(),
        packets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::EPOCH_SECS;

    const DAY: u64 = EPOCH_SECS;
    const NOW: u64 = 20_000 * DAY + 3600;

    /// An in-memory provider: mailboxes of packets, drained on fetch.
    #[derive(Default)]
    struct Provider(HashMap<MailboxId, Vec<Packet>>);

    impl Provider {
        fn deliver(&mut self, out: Outgoing) {
            self.0.entry(out.mailbox).or_default().extend(out.packets);
        }

        /// Fetch every mailbox `m` polls, feed the packets in, deliver what it sends.
        fn poll(&mut self, m: &mut Messenger, now: u64) -> Vec<Event> {
            let mut events = Vec::new();
            for mailbox in m.mailboxes(now).unwrap() {
                for packet in self.0.remove(&mailbox).unwrap_or_default() {
                    let step = m.receive(mailbox, &packet, now).unwrap();
                    events.extend(step.events);
                    for out in step.outgoing {
                        self.deliver(out);
                    }
                }
            }
            events
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
        assert_eq!(
            provider.poll(&mut alice, NOW),
            [Event::Connected("bob".into())]
        );
        assert_eq!(
            provider.poll(&mut bob, NOW),
            [Event::Connected("alice".into())]
        );
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

        provider.deliver(alice.send("bob", b"hi bob", NOW).unwrap());
        assert_eq!(provider.poll(&mut bob, NOW), [text("alice", b"hi bob")]);
        provider.deliver(bob.send("alice", b"hi alice", NOW).unwrap());
        assert_eq!(provider.poll(&mut alice, NOW), [text("bob", b"hi alice")]);

        // A message spanning several packets.
        let long = vec![b'x'; 10_000];
        let out = alice.send("bob", &long, NOW).unwrap();
        assert!(out.packets.len() > 1);
        provider.deliver(out);
        assert_eq!(provider.poll(&mut bob, NOW), [text("alice", &long)]);
    }

    #[test]
    fn mailboxes_rotate_every_epoch() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let today = alice.send("bob", b"today", NOW).unwrap();
        let tomorrow = alice.send("bob", b"tomorrow", NOW + DAY).unwrap();
        assert_ne!(today.mailbox, tomorrow.mailbox);

        provider.deliver(today);
        provider.deliver(tomorrow);
        assert_eq!(
            provider.poll(&mut bob, NOW + DAY),
            [text("alice", b"today"), text("alice", b"tomorrow")]
        );
    }

    #[test]
    fn tolerates_a_day_of_clock_skew_either_way() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        provider.deliver(alice.send("bob", b"ahead", NOW + DAY).unwrap());
        provider.deliver(alice.send("bob", b"behind", NOW - DAY).unwrap());
        let mut got = provider.poll(&mut bob, NOW);
        got.sort_by_key(|e| format!("{e:?}"));
        assert_eq!(got, [text("alice", b"ahead"), text("alice", b"behind")]);
    }

    #[test]
    fn provider_mailboxes_hold_only_sealed_packets() {
        // Nothing the provider stores contains the plaintext or libsignal's cleartext
        // PreKey fields: every packet opens only with the queue key.
        let mut provider = Provider::default();
        let (mut alice, _bob) = connected(&mut provider);
        let out = alice.send("bob", b"secret words", NOW).unwrap();
        for packet in &out.packets {
            assert!(!packet.as_bytes().windows(12).any(|w| w == b"secret words"));
            assert!(
                QueueSecret::random()
                    .unwrap()
                    .queue(epoch(NOW))
                    .unwrap()
                    .open(packet)
                    .is_err()
            );
        }
    }

    #[test]
    fn planted_bundle_does_not_block_the_real_one() {
        let mut provider = Provider::default();
        let mut alice = Messenger::new().unwrap();
        let mut bob = Messenger::new().unwrap();
        let (invite, bundle) = bob.create_invite("alice").unwrap();

        // Mallory saw the QR code and plants her own bundle first.
        let (_, mallory_bundle) = Account::generate().unwrap().create_invite().unwrap();
        let planted = outgoing(&invite.bundle_queue().unwrap(), &mallory_bundle).unwrap();
        alice.accept_invite("bob", invite).unwrap();
        let mailbox = planted.mailbox;
        for packet in &planted.packets {
            assert!(alice.receive(mailbox, packet, NOW).is_err());
        }

        provider.deliver(bundle);
        assert_eq!(
            provider.poll(&mut alice, NOW),
            [Event::Connected("bob".into())]
        );
    }

    #[test]
    fn rejects_unknown_mailboxes_and_duplicate_names() {
        let mut provider = Provider::default();
        let (mut alice, mut bob) = connected(&mut provider);
        let stray = alice.send("bob", b"x", NOW).unwrap();
        assert!(
            alice
                .receive(stray.mailbox, &stray.packets[0], NOW)
                .is_err()
        );
        assert!(bob.create_invite("alice").is_err());
        assert!(alice.send("carol", b"x", NOW).is_err());
    }
}
