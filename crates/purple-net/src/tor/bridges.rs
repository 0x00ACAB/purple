//! Tor Browser's built-in bridges.
//!
//! Copied from tor-browser-build's `projects/tor-expert-bundle/pt_config.json`. Refresh them
//! when Tor Browser does; old lines stop working as bridges are retired or blocked. Until
//! the list is fetched these are empty, and the fallback goes from plain Tor straight to
//! asking the user.

use purple_ipc::Route;

const OBFS4: &[&str] = &[
    // One line per entry of pt_config.json's "bridges"."obfs4", verbatim.
];
const SNOWFLAKE: &[&str] = &[
    // "bridges"."snowflake".
];
const WEBTUNNEL: &[&str] = &[
    // "bridges"."webtunnel".
];

/// The built-in lines for `route`.
#[must_use]
pub const fn builtin(route: Route) -> &'static [&'static str] {
    match route {
        Route::Obfs4 => OBFS4,
        Route::Snowflake => SNOWFLAKE,
        Route::WebTunnel => WEBTUNNEL,
        Route::Tor | Route::Pasted | Route::Direct => &[],
    }
}

/// tor's `ClientTransportPlugin` value for `route`'s transport. The binaries come from the
/// system packages, visible in tor's sandbox under /usr.
#[must_use]
pub const fn plugin(route: Route) -> Option<&'static str> {
    match route {
        Route::Obfs4 => Some("obfs4 exec /usr/bin/lyrebird"),
        Route::WebTunnel => Some("webtunnel exec /usr/bin/lyrebird"),
        Route::Snowflake => Some("snowflake exec /usr/bin/snowflake-client"),
        Route::Tor | Route::Pasted | Route::Direct => None,
    }
}

/// Bridge types purple has lines for.
#[must_use]
pub fn available() -> Vec<Route> {
    [Route::Obfs4, Route::Snowflake, Route::WebTunnel]
        .into_iter()
        .filter(|r| !builtin(*r).is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tor::control::check_bridge_line;

    #[test]
    fn every_builtin_line_is_safe_and_matches_its_transport() {
        for (route, name) in [
            (Route::Obfs4, "obfs4 "),
            (Route::Snowflake, "snowflake "),
            (Route::WebTunnel, "webtunnel "),
        ] {
            for line in builtin(route) {
                check_bridge_line(line).unwrap();
                assert!(line.starts_with(name), "{line}");
            }
            assert!(plugin(route).is_some(), "{route:?} has a plugin");
        }
        assert!(builtin(Route::Tor).is_empty() && builtin(Route::Direct).is_empty());
        assert!(available().iter().all(|r| !builtin(*r).is_empty()));
    }
}
