//! Tor Browser's built-in bridges.
//!
//! Copied from tor-browser-build's `projects/tor-expert-bundle/pt_config.json` on
//! 2026-11-05. Refresh them when Tor Browser does; old lines stop working as bridges are
//! retired or blocked. Tor Browser has no built-in webtunnel bridges, so neither does
//! purple; pasted ones work.

use std::path::Path;

use purple_ipc::Route;

const OBFS4: &[&str] = &[
    "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
    "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
];
const SNOWFLAKE: &[&str] = &[
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
    "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn",
];
const WEBTUNNEL: &[&str] = &[];

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
        // lyrebird has carried Snowflake since Tor Browser 14.5.
        Route::Snowflake => Some("snowflake exec /usr/bin/lyrebird"),
        Route::Tor | Route::Pasted | Route::Direct => None,
    }
}

/// Bridge types purple has lines for and whose plugin is installed.
#[must_use]
pub fn available() -> Vec<Route> {
    available_with(Path::exists)
}

/// [`available`], with `installed` saying whether a plugin binary exists.
pub fn available_with(installed: impl Fn(&Path) -> bool) -> Vec<Route> {
    [Route::Obfs4, Route::Snowflake, Route::WebTunnel]
        .into_iter()
        .filter(|r| !builtin(*r).is_empty())
        .filter(|r| plugin(*r).and_then(plugin_binary).is_some_and(&installed))
        .collect()
}

/// The binary in a `ClientTransportPlugin` value: the word after `exec`.
fn plugin_binary(plugin: &str) -> Option<&Path> {
    let mut words = plugin.split_whitespace().skip_while(|w| *w != "exec");
    words.next()?;
    words.next().map(Path::new)
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
        assert!(!builtin(Route::Obfs4).is_empty() && !builtin(Route::Snowflake).is_empty());
        assert!(available().iter().all(|r| !builtin(*r).is_empty()));
    }

    #[test]
    fn routes_without_their_plugin_installed_are_not_available() {
        assert!(available_with(|_| false).is_empty());
        assert_eq!(available_with(|_| true), [Route::Obfs4, Route::Snowflake]);
    }
}
