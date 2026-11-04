//! Cover traffic: one packet per tick, with ticks at exponentially distributed intervals
//! (a Poisson process, as in Loopix).
//!
//! A tick writes the oldest queued real packet if there is one, otherwise a cover packet:
//! random bytes into a random box. Real packets are sealed and look random too, so an
//! observer sees the same stream whether or not the user is talking; sending a message
//! only adds queueing delay.

use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use purple_ipc::{BoxRef, PACKET_LEN, Packet, SEED_LEN, StreamSeed};
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
    queue: VecDeque<(BoxRef, Packet)>,
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
    pub fn enqueue(&mut self, at: BoxRef, packet: Packet) {
        self.queue.push_back((at, packet));
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
        let sent = if let Some((at, packet)) = self.queue.pop_front() {
            self.transport.write(&at, packet)?;
            Sent::Real
        } else {
            let (at, packet) = cover_packet()?;
            self.transport.write(&at, packet)?;
            Sent::Cover
        };
        let now = Instant::now();
        self.next_tick = now.checked_add(sample_delay(self.mean)).unwrap_or(now);
        Ok(sent)
    }

    /// Read a box right away. Reads aren't scheduled here: `purple-core` already polls on
    /// a fixed clock with padded rounds.
    ///
    /// # Errors
    /// Fails if the transport fails.
    pub fn read(&mut self, at: &BoxRef) -> io::Result<Option<Packet>> {
        self.transport.read(at)
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

/// Random bytes into a random box. Indistinguishable from a sealed real packet.
fn cover_packet() -> io::Result<(BoxRef, Packet)> {
    let mut rng = rand::rng();
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);
    let at = BoxRef {
        stream: StreamSeed(seed),
        index: rng.random(),
    };
    let mut bytes = vec![0u8; PACKET_LEN];
    rng.fill_bytes(&mut bytes);
    Ok((at, Packet::from_slice(&bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records every packet written.
    #[derive(Default)]
    struct Recorder(Vec<(BoxRef, Packet)>);

    impl Transport for Recorder {
        fn write(&mut self, at: &BoxRef, packet: Packet) -> io::Result<()> {
            self.0.push((*at, packet));
            Ok(())
        }

        fn read(&mut self, _: &BoxRef) -> io::Result<Option<Packet>> {
            Ok(None)
        }
    }

    fn at(seed: u8) -> BoxRef {
        BoxRef {
            stream: StreamSeed([seed; SEED_LEN]),
            index: 0,
        }
    }

    fn packet(byte: u8) -> Packet {
        Packet::from_slice(&[byte; PACKET_LEN]).unwrap()
    }

    #[test]
    fn every_tick_sends_exactly_one_packet_real_ones_first_in_order() {
        let mut s = Scheduler::new(Recorder::default(), Duration::from_secs(1));
        s.enqueue(at(1), packet(1));
        s.enqueue(at(2), packet(2));
        let sent: Vec<Sent> = (0..4).map(|_| s.tick().unwrap()).collect();
        assert_eq!(sent, [Sent::Real, Sent::Real, Sent::Cover, Sent::Cover]);

        let log = &s.transport.0;
        assert_eq!(log.len(), 4);
        assert_eq!(log[0], (at(1), packet(1)));
        assert_eq!(log[1], (at(2), packet(2)));
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
