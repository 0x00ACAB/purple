//! The order purple tries routes to the store in.
//!
//! Plain Tor, then each built-in bridge type, then the user's choice. Pure logic: the caller feeds it tor's bootstrap progress
//! and the user's answers, and carries out the actions it returns. Nothing here is saved,
//! so every start begins with plain Tor.

use std::time::{Duration, Instant};

use purple_ipc::torctl::Notice;
use purple_ipc::{NetChoice, NetStatus, Route};

use crate::bridges;
use crate::control::check_bridge_line;

/// How long a route may go without bootstrap progress before the next one is tried.
pub const STALL: Duration = Duration::from_mins(1);

/// What the caller should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Switch tor to the built-in bridges of this type.
    UseBridges(Route),
    /// Switch tor to pasted bridge lines, run through `plugin`.
    UsePasted {
        /// tor's `ClientTransportPlugin` value for the lines' transport.
        plugin: &'static str,
        /// The lines, each already checked.
        lines: Vec<String>,
    },
    /// Turn bridges off.
    NoBridges,
    /// The user chose direct; core asks the launcher for the relay.
    GoDirect,
    /// Tell core (and the user) how it's going.
    Report(NetStatus),
    /// Tell the user something that changes nothing.
    Notice(Notice),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Trying {
        route: Route,
        best: u8,
        since: Instant,
    },
    Connected(Route),
    Blocked,
    /// The user chose direct; waiting for core to say whether the relay started.
    DirectPending,
    Direct,
}

/// Where the chain is.
#[derive(Debug)]
pub struct Fallback {
    /// Built-in routes still to try, in order.
    next: Vec<Route>,
    direct_available: bool,
    state: State,
    /// How long a route may go without progress.
    stall: Duration,
}

impl Fallback {
    /// Start with plain Tor. `builtin` lists the bridge types purple has lines for;
    /// `direct_available` says whether the config has a direct address.
    #[must_use]
    pub fn new(builtin: &[Route], direct_available: bool, now: Instant) -> Self {
        Self::with_stall(builtin, direct_available, now, STALL)
    }

    /// The same, giving up on a route after `stall` without progress instead of [`STALL`].
    #[must_use]
    pub fn with_stall(
        builtin: &[Route],
        direct_available: bool,
        now: Instant,
        stall: Duration,
    ) -> Self {
        let order = [Route::Obfs4, Route::Snowflake, Route::WebTunnel];
        Self {
            next: order
                .into_iter()
                .filter(|r| builtin.contains(r))
                .rev()
                .collect(),
            direct_available,
            stall,
            state: State::Trying {
                route: Route::Tor,
                best: 0,
                since: now,
            },
        }
    }

    /// The route being tried or used, if any.
    #[must_use]
    pub const fn route(&self) -> Option<Route> {
        match self.state {
            State::Trying { route, .. } | State::Connected(route) => Some(route),
            State::DirectPending | State::Direct => Some(Route::Direct),
            State::Blocked => None,
        }
    }

    /// Tor's bootstrap progress at `now`.
    pub fn progress(&mut self, percent: u8, now: Instant) -> Vec<Action> {
        let State::Trying { route, best, since } = self.state else {
            return Vec::new();
        };
        if percent >= 100 {
            self.state = State::Connected(route);
            return vec![Action::Report(NetStatus::Connected { route })];
        }
        if percent > best {
            self.state = State::Trying {
                route,
                best: percent,
                since: now,
            };
            return vec![Action::Report(NetStatus::Connecting { route, percent })];
        }
        if now.saturating_duration_since(since) < self.stall {
            return Vec::new();
        }
        let Some(next) = self.next.pop() else {
            self.state = State::Blocked;
            return vec![Action::NoBridges, Action::Report(NetStatus::Blocked)];
        };
        self.state = State::Trying {
            route: next,
            best: 0,
            since: now,
        };
        vec![
            Action::UseBridges(next),
            Action::Report(NetStatus::Connecting {
                route: next,
                percent: 0,
            }),
        ]
    }

    /// The user's answer to [`NetStatus::Blocked`].
    pub fn choose(&mut self, choice: NetChoice, now: Instant) -> Vec<Action> {
        match (&self.state, choice) {
            (State::Direct | State::DirectPending, _) => {
                vec![Action::Notice(Notice::AlreadyDirect)]
            }
            (State::Blocked, NetChoice::Direct) if self.direct_available => {
                self.state = State::DirectPending;
                vec![Action::GoDirect]
            }
            (State::Blocked, NetChoice::Direct) => vec![Action::Notice(Notice::NoDirectAddress)],
            (State::Blocked, NetChoice::Bridges(text)) => {
                let lines: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect();
                if lines.is_empty() {
                    return vec![Action::Notice(Notice::NoBridgeLines)];
                }
                let plugin = match pasted_plugin(&lines) {
                    Ok(plugin) if lines.iter().all(|l| check_bridge_line(l).is_ok()) => plugin,
                    Ok(_) | Err(_) => return vec![Action::Notice(Notice::BadBridgeLines)],
                };
                self.state = State::Trying {
                    route: Route::Pasted,
                    best: 0,
                    since: now,
                };
                vec![
                    Action::UsePasted { plugin, lines },
                    Action::Report(NetStatus::Connecting {
                        route: Route::Pasted,
                        percent: 0,
                    }),
                ]
            }
            (State::Trying { .. } | State::Connected(_), _) => {
                vec![Action::Notice(Notice::StillTrying)]
            }
        }
    }

    /// core says the relay is up and purple-net uses it.
    pub fn direct_up(&mut self) -> Vec<Action> {
        if self.state != State::DirectPending {
            return Vec::new();
        }
        self.state = State::Direct;
        vec![Action::Report(NetStatus::Connected {
            route: Route::Direct,
        })]
    }

    /// core says the relay couldn't start; the user can choose again.
    pub fn direct_failed(&mut self) -> Vec<Action> {
        if self.state != State::DirectPending {
            return Vec::new();
        }
        self.state = State::Blocked;
        vec![Action::Report(NetStatus::Blocked)]
    }
}

/// The `ClientTransportPlugin` value for pasted `lines`, which must all be one type that
/// purple has a plugin for.
///
/// # Errors
/// [`Notice::BadBridgeLines`] for mixed or unsupported transports.
pub fn pasted_plugin(lines: &[String]) -> Result<&'static str, Notice> {
    let mut kinds = lines
        .iter()
        .map(|l| l.split_whitespace().next().unwrap_or(""));
    let first = kinds.next().ok_or(Notice::BadBridgeLines)?;
    if kinds.any(|k| k != first) {
        return Err(Notice::BadBridgeLines);
    }
    let route = match first {
        "obfs4" => Route::Obfs4,
        "snowflake" => Route::Snowflake,
        "webtunnel" => Route::WebTunnel,
        _ => return Err(Notice::BadBridgeLines),
    };
    bridges::plugin(route).ok_or(Notice::BadBridgeLines)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Route; 3] = [Route::Obfs4, Route::Snowflake, Route::WebTunnel];

    fn reports(actions: &[Action]) -> Vec<NetStatus> {
        actions
            .iter()
            .filter_map(|a| {
                if let Action::Report(s) = a {
                    Some(*s)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn progress_resets_the_stall_timer_and_100_connects() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&ALL, true, t0);
        f.progress(10, t0 + Duration::from_secs(50));
        let a = f.progress(20, t0 + Duration::from_secs(100));
        assert!(
            !a.iter().any(|act| matches!(act, Action::UseBridges(_))),
            "progress keeps the route"
        );
        let done = f.progress(100, t0 + Duration::from_secs(101));
        assert_eq!(reports(&done), [NetStatus::Connected { route: Route::Tor }]);
    }

    #[test]
    fn each_stall_moves_to_the_next_route_then_blocks() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&ALL, true, t0);
        let mut t = t0;
        let mut used = Vec::new();
        for _ in 0..3 {
            t += STALL;
            for a in f.progress(0, t) {
                if let Action::UseBridges(r) = a {
                    used.push(r);
                }
            }
        }
        assert_eq!(used, ALL);
        let a = f.progress(0, t + STALL);
        assert_eq!(reports(&a), [NetStatus::Blocked]);
        // Once blocked, more stalls don't repeat the report.
        assert!(reports(&f.progress(0, t + STALL * 2)).is_empty());
    }

    #[test]
    fn missing_builtin_routes_are_skipped() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[Route::Snowflake], true, t0);
        let a = f.progress(0, t0 + STALL);
        assert!(
            a.iter()
                .any(|act| matches!(act, Action::UseBridges(Route::Snowflake)))
        );
        let blocked = f.progress(0, t0 + STALL * 2);
        assert_eq!(reports(&blocked), [NetStatus::Blocked]);
    }

    fn notices(actions: &[Action]) -> Vec<Notice> {
        actions
            .iter()
            .filter_map(|a| {
                if let Action::Notice(n) = a {
                    Some(*n)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn direct_before_blocked_is_a_notice() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&ALL, true, t0);
        let got = f.choose(NetChoice::Direct, t0);
        assert_eq!(notices(&got), [Notice::StillTrying]);
        assert!(!got.contains(&Action::GoDirect));
    }

    #[test]
    fn direct_after_blocked_waits_for_the_relay() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        assert_eq!(f.choose(NetChoice::Direct, t0), [Action::GoDirect]);
        assert_eq!(
            notices(&f.choose(NetChoice::Direct, t0)),
            [Notice::AlreadyDirect]
        );
        assert_eq!(
            reports(&f.direct_up()),
            [NetStatus::Connected {
                route: Route::Direct
            }]
        );
        assert_eq!(
            notices(&f.choose(NetChoice::Direct, t0)),
            [Notice::AlreadyDirect]
        );
    }

    #[test]
    fn a_failed_relay_goes_back_to_blocked() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        f.choose(NetChoice::Direct, t0);
        assert_eq!(reports(&f.direct_failed()), [NetStatus::Blocked]);
        assert_eq!(
            f.choose(NetChoice::Direct, t0),
            [Action::GoDirect],
            "can try again"
        );
    }

    #[test]
    fn late_direct_answers_are_ignored() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&ALL, true, t0);
        assert!(f.direct_up().is_empty());
        assert!(f.direct_failed().is_empty());
        assert_eq!(f.route(), Some(Route::Tor), "still trying plain Tor");
    }

    #[test]
    fn direct_without_a_configured_direct_address_says_so() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], false, t0);
        f.progress(0, t0 + STALL);
        assert_eq!(
            notices(&f.choose(NetChoice::Direct, t0)),
            [Notice::NoDirectAddress]
        );
    }

    #[test]
    fn pasted_bridges_get_their_own_try_then_block_again() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        let got = f.choose(
            NetChoice::Bridges("obfs4 192.0.2.1:443 F cert=c iat-mode=0\n\n".into()),
            t0 + STALL * 2,
        );
        assert!(got.iter().any(|a| matches!(a,
            Action::UsePasted { plugin: "obfs4 exec /usr/bin/lyrebird", lines } if lines.len() == 1)));
        assert_eq!(
            reports(&got),
            [NetStatus::Connecting {
                route: Route::Pasted,
                percent: 0
            }]
        );
        assert_eq!(
            reports(&f.progress(0, t0 + STALL * 3)),
            [NetStatus::Blocked]
        );
    }

    #[test]
    fn bad_pasted_lines_are_refused_with_a_notice() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        for text in [
            "obfs4 192.0.2.1:443 F cert=c iat-mode=0\nsnowflake 192.0.2.3:80 F",
            "meek_lite 192.0.2.2:80 F",
            "obfs4 1.2.3.4:1\" Bridge=\"x",
        ] {
            let got = f.choose(NetChoice::Bridges(text.into()), t0);
            assert_eq!(notices(&got), [Notice::BadBridgeLines], "{text}");
            assert!(reports(&got).is_empty());
        }
        assert_eq!(
            notices(&f.choose(NetChoice::Bridges(" \n".into()), t0)),
            [Notice::NoBridgeLines]
        );
        assert_eq!(
            f.choose(NetChoice::Direct, t0),
            [Action::GoDirect],
            "still Blocked"
        );
    }

    #[test]
    fn pasted_lines_pick_their_transport() {
        let obfs4 = vec!["obfs4 192.0.2.1:443 F cert=c iat-mode=0".to_owned()];
        assert_eq!(pasted_plugin(&obfs4), Ok("obfs4 exec /usr/bin/lyrebird"));
        let snow = vec!["snowflake 192.0.2.3:80 F".to_owned()];
        assert_eq!(pasted_plugin(&snow), Ok("snowflake exec /usr/bin/lyrebird"));
    }

    #[test]
    fn a_new_fallback_always_starts_with_plain_tor() {
        // Nothing is saved: a restart after choosing direct begins at Tor again.
        let f = Fallback::new(&ALL, true, Instant::now());
        assert_eq!(f.route(), Some(Route::Tor));
    }
}
