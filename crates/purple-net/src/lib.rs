//! Transports that carry packets between mailboxes, and the request loop that serves
//! them to `purple-core` (or, in `purple-devprovider`, to other purple instances).

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, PoisonError};

use purple_ipc::{MailboxId, NetMsg, Packet};

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

/// Answer [`NetMsg`] requests from `peer` with `transport` until `peer` closes the stream.
///
/// # Errors
/// Fails on an I/O error, a malformed request, or a message only the serving side may send.
pub fn serve(peer: &mut (impl Read + Write), transport: &mut impl Transport) -> io::Result<()> {
    while let Some(msg) = NetMsg::read_from(peer)? {
        match msg {
            NetMsg::Send { mailbox, packet } => transport.send(&mailbox, packet)?,
            NetMsg::Fetch { mailbox } => {
                for packet in transport.fetch(&mailbox)? {
                    NetMsg::Delivered { mailbox, packet }.write_to(peer)?;
                }
                NetMsg::FetchDone { mailbox }.write_to(peer)?;
            }
            NetMsg::Delivered { .. } | NetMsg::FetchDone { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer sent a message only the serving side may send",
                ));
            }
        }
    }
    Ok(())
}

/// Forwards to a `purple-devprovider` over TCP. Development only: the provider sees every
/// mailbox this client uses, with no mixnet in between.
#[derive(Debug)]
pub struct DevProviderTransport {
    stream: TcpStream,
}

impl DevProviderTransport {
    /// Connect to the dev provider at `addr`.
    ///
    /// # Errors
    /// Fails if the connection fails.
    pub fn connect(addr: &str) -> io::Result<Self> {
        Ok(Self {
            stream: TcpStream::connect(addr)?,
        })
    }
}

impl Transport for DevProviderTransport {
    fn send(&mut self, mailbox: &MailboxId, packet: Packet) -> io::Result<()> {
        NetMsg::Send {
            mailbox: *mailbox,
            packet,
        }
        .write_to(&mut self.stream)
    }

    fn fetch(&mut self, mailbox: &MailboxId) -> io::Result<Vec<Packet>> {
        NetMsg::Fetch { mailbox: *mailbox }.write_to(&mut self.stream)?;
        let mut packets = Vec::new();
        loop {
            match NetMsg::read_from(&mut self.stream)? {
                Some(NetMsg::Delivered {
                    mailbox: from,
                    packet,
                }) if from == *mailbox => {
                    packets.push(packet);
                }
                Some(NetMsg::FetchDone { mailbox: from }) if from == *mailbox => {
                    return Ok(packets);
                }
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected reply from the dev provider",
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "dev provider closed the connection",
                    ));
                }
            }
        }
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
    fn dev_provider_transport_round_trips_through_serve() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve(&mut stream, &mut FakeTransport::default()).unwrap();
        });
        let mut client = DevProviderTransport::connect(&addr).unwrap();
        let mailbox = MailboxId([4; 32]);
        client.send(&mailbox, packet(1)).unwrap();
        client.send(&mailbox, packet(2)).unwrap();
        assert_eq!(client.fetch(&mailbox).unwrap(), vec![packet(1), packet(2)]);
        assert!(client.fetch(&mailbox).unwrap().is_empty());
        drop(client);
        server.join().unwrap();
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
