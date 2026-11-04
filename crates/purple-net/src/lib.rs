//! Transports that carry packets between mailboxes.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use purple_ipc::{MailboxId, Packet};

/// Moves fixed-size packets to and from mailboxes. The mixnet client implements this; so
/// does [`FakeTransport`] for tests and local development.
pub trait Transport {
    /// Queue `packet` for delivery to `mailbox`.
    ///
    /// # Errors
    /// Fails if the packet can't be handed to the network.
    fn send(&mut self, mailbox: &MailboxId, packet: Packet) -> io::Result<()>;

    /// Take every packet waiting in `mailbox`.
    ///
    /// # Errors
    /// Fails if the mailbox can't be reached.
    fn fetch(&mut self, mailbox: &MailboxId) -> io::Result<Vec<Packet>>;
}

/// In-memory stand-in for the mixnet. Clones share one network, so two clones behave like
/// two clients talking through the same providers.
#[derive(Clone, Debug, Default)]
pub struct FakeTransport {
    mailboxes: Arc<Mutex<HashMap<MailboxId, VecDeque<Packet>>>>,
}

impl Transport for FakeTransport {
    fn send(&mut self, mailbox: &MailboxId, packet: Packet) -> io::Result<()> {
        self.mailboxes
            .lock()
            .map_err(poisoned)?
            .entry(*mailbox)
            .or_default()
            .push_back(packet);
        Ok(())
    }

    fn fetch(&mut self, mailbox: &MailboxId) -> io::Result<Vec<Packet>> {
        let mut mailboxes = self.mailboxes.lock().map_err(poisoned)?;
        Ok(mailboxes.remove(mailbox).map(Vec::from).unwrap_or_default())
    }
}

fn poisoned<T>(_: PoisonError<T>) -> io::Error {
    io::Error::other("fake transport lock poisoned")
}

#[cfg(test)]
mod tests {
    use purple_ipc::PACKET_LEN;

    use super::*;

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    #[test]
    fn fetch_returns_packets_in_order_then_empties() {
        let mut net = FakeTransport::default();
        let mailbox = MailboxId([1; 32]);
        net.send(&mailbox, packet(1)).unwrap();
        net.send(&mailbox, packet(2)).unwrap();
        assert_eq!(net.fetch(&mailbox).unwrap(), vec![packet(1), packet(2)]);
        assert!(net.fetch(&mailbox).unwrap().is_empty());
    }

    #[test]
    fn mailboxes_are_isolated() {
        let mut net = FakeTransport::default();
        net.send(&MailboxId([1; 32]), packet(1)).unwrap();
        assert!(net.fetch(&MailboxId([2; 32])).unwrap().is_empty());
    }

    #[test]
    fn clones_share_one_network() {
        let mut alice = FakeTransport::default();
        let mut bob = alice.clone();
        let mailbox = MailboxId([3; 32]);
        alice.send(&mailbox, packet(7)).unwrap();
        assert_eq!(bob.fetch(&mailbox).unwrap(), vec![packet(7)]);
    }
}
