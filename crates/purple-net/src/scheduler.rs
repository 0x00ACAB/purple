//! Cover traffic: one packet per tick, with ticks at exponentially distributed intervals
//! (a Poisson process, as in Loopix).
//!
//! A tick sends the oldest queued real packet if there is one, otherwise a cover packet:
//! random bytes to a random mailbox. Real packets are sealed and look random too, so an
//! observer sees the same stream whether or not the user is talking; sending a message
//! only adds queueing delay.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use purple_ipc::{MAILBOX_ID_LEN, MailboxId, PACKET_LEN, Packet};
use rand::{Rng, RngCore};

use crate::Transport;

/// Longest gap between ticks, as a multiple of the mean. Caps the exponential's long tail
/// so a message is never stuck behind one huge gap.
const MAX_DELAY_FACTOR: f64 = 10.0;
/// Shortest gap between ticks.
const MIN_DELAY: Duration = Duration::from_millis(1);

/// What a tick sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// A queued packet from `purple-core`.
    Real,
    /// A cover packet.
    Cover,
}

/// Sends queued packets, and cover packets in between, at a Poisson rate.
#[derive(Debug)]
pub struct Scheduler<T> {
    transport: T,
    queue: VecDeque<(MailboxId, Packet)>,
    mean: Duration,
    next_tick: Instant,
}

impl<T: Transport> Scheduler<T> {
    /// A scheduler sending on average one packet every `mean`.
    pub fn new(transport: T, mean: Duration) -> Self {
        let now = Instant::now();
        Self {
            transport,
            queue: VecDeque::new(),
            mean,
            next_tick: now.checked_add(sample_delay(mean)).unwrap_or(now),
        }
    }

    /// Queue a real packet for the next free tick.
    pub fn enqueue(&mut self, mailbox: MailboxId, packet: Packet) {
        self.queue.push_back((mailbox, packet));
    }

    /// Real packets waiting to be sent.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// When the next packet should go out.
    #[must_use]
    pub const fn next_tick(&self) -> Instant {
        self.next_tick
    }

    /// Send one packet (real if any is queued, else cover) and schedule the next tick.
    ///
    /// # Errors
    /// Fails if the transport fails. A real packet that fails to send is dropped.
    pub fn tick(&mut self) -> io::Result<Sent> {
        let sent = if let Some((mailbox, packet)) = self.queue.pop_front() {
            self.transport.send(&mailbox, packet)?;
            Sent::Real
        } else {
            let (mailbox, packet) = cover_packet()?;
            self.transport.send(&mailbox, packet)?;
            Sent::Cover
        };
        let now = Instant::now();
        self.next_tick = now.checked_add(sample_delay(self.mean)).unwrap_or(now);
        Ok(sent)
    }

    /// Fetch a mailbox right away. Fetches aren't scheduled here: `purple-core` already
    /// polls on a fixed clock with padded rounds.
    ///
    /// # Errors
    /// Fails if the transport fails.
    pub fn fetch(&mut self, mailbox: &MailboxId) -> io::Result<Vec<Packet>> {
        self.transport.fetch(mailbox)
    }
}

/// An exponentially distributed delay with the given mean, clamped to
/// [`MIN_DELAY`, `MAX_DELAY_FACTOR` × mean].
#[must_use]
pub fn sample_delay(mean: Duration) -> Duration {
    // 1 - u is in (0, 1], so its log is finite and ≤ 0.
    let u: f64 = rand::rng().random();
    let factor = (-(1.0 - u).ln()).min(MAX_DELAY_FACTOR);
    mean.mul_f64(factor).max(MIN_DELAY)
}

/// Random bytes to a random mailbox. Indistinguishable from a sealed real packet.
fn cover_packet() -> io::Result<(MailboxId, Packet)> {
    let mut rng = rand::rng();
    let mut mailbox = [0u8; MAILBOX_ID_LEN];
    rng.fill_bytes(&mut mailbox);
    let mut bytes = vec![0u8; PACKET_LEN];
    rng.fill_bytes(&mut bytes);
    Ok((MailboxId(mailbox), Packet::from_slice(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every packet sent.
    #[derive(Default)]
    struct Recorder(Vec<(MailboxId, Packet)>);

    impl Transport for Recorder {
        fn send(&mut self, mailbox: &MailboxId, packet: Packet) -> io::Result<()> {
            self.0.push((*mailbox, packet));
            Ok(())
        }

        fn fetch(&mut self, _: &MailboxId) -> io::Result<Vec<Packet>> {
            Ok(Vec::new())
        }
    }

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    #[test]
    fn every_tick_sends_exactly_one_packet_real_ones_first_in_order() {
        let mut s = Scheduler::new(Recorder::default(), Duration::from_secs(1));
        s.enqueue(MailboxId([1; 32]), packet(1));
        s.enqueue(MailboxId([2; 32]), packet(2));
        let sent: Vec<Sent> = (0..4).map(|_| s.tick().unwrap()).collect();
        assert_eq!(sent, [Sent::Real, Sent::Real, Sent::Cover, Sent::Cover]);

        let log = &s.transport.0;
        assert_eq!(log.len(), 4);
        assert_eq!(log[0], (MailboxId([1; 32]), packet(1)));
        assert_eq!(log[1], (MailboxId([2; 32]), packet(2)));
        assert_eq!(s.queued(), 0);
    }

    #[test]
    fn cover_packets_are_random_each_time() {
        let mut s = Scheduler::new(Recorder::default(), Duration::from_secs(1));
        s.tick().unwrap();
        s.tick().unwrap();
        let [(m1, p1), (m2, p2)] = [&s.transport.0[0], &s.transport.0[1]];
        assert_ne!(m1, m2);
        assert_ne!(p1, p2);
        assert!(p1.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn delays_are_exponential_with_the_requested_mean() {
        let mean = Duration::from_millis(100);
        let samples: Vec<Duration> = (0..20_000).map(|_| sample_delay(mean)).collect();
        let total: Duration = samples.iter().sum();
        let average = total / 20_000;
        assert!(
            average > mean.mul_f64(0.95) && average < mean.mul_f64(1.05),
            "{average:?}"
        );
        assert!(
            samples
                .iter()
                .all(|d| *d >= MIN_DELAY && *d <= mean.mul_f64(MAX_DELAY_FACTOR))
        );
        // An exponential has no memory: about 37% of gaps exceed the mean.
        let over = samples.iter().filter(|d| **d > mean).count();
        assert!((6_800..=8_000).contains(&over), "{over}");
    }

    #[test]
    fn next_tick_moves_forward() {
        let mut s = Scheduler::new(Recorder::default(), Duration::from_millis(50));
        let before = Instant::now();
        s.tick().unwrap();
        assert!(s.next_tick() >= before);
    }
}
