//! The order purple-net tries routes to the store in.
//!
//! Plain Tor, then each built-in bridge type, then the user's choice. Pure logic: the caller feeds it tor's bootstrap progress
//! and the user's answers, and carries out the actions it returns. Nothing here is saved,
//! so every start begins with plain Tor.

use std::time::{Duration, Instant};

use purple_ipc::{NetChoice, NetStatus, Route};

/// How long a route may go without bootstrap progress before the next one is tried.
pub const STALL: Duration = Duration::from_mins(1);

/// What the caller should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Switch tor to the built-in bridges of this type.
    UseBridges(Route),
    /// Switch tor to these pasted bridge lines.
    UsePasted(Vec<String>),
    /// Turn bridges off.
    NoBridges,
    /// Stop using Tor and connect to the store directly, until purple exits.
    UseDirect,
    /// Tell core (and the user) how it's going.
    Report(NetStatus),
    /// Tell the user something that changes nothing.
    Say(&'static str),
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
    Direct,
}

/// Where the chain is.
#[derive(Debug)]
pub struct Fallback {
    /// Built-in routes still to try, in order.
    next: Vec<Route>,
    direct_available: bool,
    state: State,
}

impl Fallback {
    /// Start with plain Tor. `builtin` lists the bridge types purple has lines for;
    /// `direct_available` says whether the config has a direct address.
    #[must_use]
    pub fn new(builtin: &[Route], direct_available: bool, now: Instant) -> Self {
        let order = [Route::Obfs4, Route::Snowflake, Route::WebTunnel];
        Self {
            next: order
                .into_iter()
                .filter(|r| builtin.contains(r))
                .rev()
                .collect(),
            direct_available,
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
            State::Direct => Some(Route::Direct),
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
        if now.saturating_duration_since(since) < STALL {
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
        if self.state != State::Blocked {
            return vec![Action::Say(
                "purple is still trying Tor; that choice comes if every route fails",
            )];
        }
        match choice {
            NetChoice::Direct if self.direct_available => {
                self.state = State::Direct;
                vec![
                    Action::UseDirect,
                    Action::Report(NetStatus::Connected {
                        route: Route::Direct,
                    }),
                ]
            }
            NetChoice::Direct => vec![Action::Say("this store has no direct address configured")],
            NetChoice::Bridges(text) => {
                let lines: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect();
                if lines.is_empty() {
                    return vec![Action::Say("no bridge lines in that")];
                }
                self.state = State::Trying {
                    route: Route::Pasted,
                    best: 0,
                    since: now,
                };
                vec![
                    Action::UsePasted(lines),
                    Action::Report(NetStatus::Connecting {
                        route: Route::Pasted,
                        percent: 0,
                    }),
                ]
            }
        }
    }
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

    #[test]
    fn direct_before_blocked_is_ignored() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&ALL, true, t0);
        let a = f.choose(NetChoice::Direct, t0);
        assert!(!a.iter().any(|act| matches!(act, Action::UseDirect)));
        assert!(a.iter().any(|act| matches!(act, Action::Say(_))));
    }

    #[test]
    fn direct_after_blocked_is_used_once() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        let a = f.choose(NetChoice::Direct, t0);
        assert!(a.iter().any(|act| matches!(act, Action::UseDirect)));
        assert_eq!(
            reports(&a),
            [NetStatus::Connected {
                route: Route::Direct
            }]
        );
        assert!(
            !f.choose(NetChoice::Direct, t0)
                .iter()
                .any(|act| matches!(act, Action::UseDirect))
        );
    }

    #[test]
    fn direct_without_a_configured_direct_address_says_so() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], false, t0);
        f.progress(0, t0 + STALL);
        let a = f.choose(NetChoice::Direct, t0);
        assert!(!a.iter().any(|act| matches!(act, Action::UseDirect)));
        assert!(a.iter().any(|act| matches!(act, Action::Say(_))));
    }

    #[test]
    fn pasted_bridges_get_their_own_try_then_block_again() {
        let t0 = Instant::now();
        let mut f = Fallback::new(&[], true, t0);
        f.progress(0, t0 + STALL);
        let a = f.choose(
            NetChoice::Bridges("obfs4 192.0.2.1:443 F cert=c iat-mode=0\n\n".into()),
            t0 + STALL * 2,
        );
        assert!(
            a.iter()
                .any(|act| matches!(act, Action::UsePasted(l) if l.len() == 1))
        );
        assert_eq!(
            reports(&a),
            [NetStatus::Connecting {
                route: Route::Pasted,
                percent: 0
            }]
        );
        let blocked = f.progress(0, t0 + STALL * 3);
        assert_eq!(reports(&blocked), [NetStatus::Blocked]);
    }

    #[test]
    fn a_new_fallback_always_starts_with_plain_tor() {
        // Nothing is saved: a restart after choosing direct begins at Tor again.
        let f = Fallback::new(&ALL, true, Instant::now());
        assert_eq!(f.route(), Some(Route::Tor));
    }
}
