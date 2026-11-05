//! The torrc purple runs tor with: a client only, reachable through Unix sockets in the
//! directory purple-net sees, with a circuit per SOCKS username.

use crate::sandbox::{TOR_CONTROL, TOR_COOKIE, TOR_DATA_DIR, TOR_SOCKS};

pub(crate) fn torrc() -> String {
    format!(
        "DataDirectory {TOR_DATA_DIR}\n\
         SocksPort unix:{TOR_SOCKS} IsolateSOCKSAuth\n\
         ControlPort unix:{TOR_CONTROL}\n\
         CookieAuthentication 1\n\
         CookieAuthFile {TOR_COOKIE}\n\
         ClientOnly 1\n\
         AvoidDiskWrites 1\n\
         Log notice stderr\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn torrc_isolates_by_socks_auth_and_uses_purples_paths() {
        let rc = torrc();
        assert!(rc.contains("SocksPort unix:/run/tor/socks.sock IsolateSOCKSAuth"));
        assert!(rc.contains("ControlPort unix:/run/tor/control.sock"));
        assert!(rc.contains("CookieAuthentication 1"));
        assert!(rc.contains("CookieAuthFile /run/tor/control.cookie"));
        assert!(rc.contains("DataDirectory /var/lib/tor"));
        assert!(rc.contains("ClientOnly 1"));
        assert!(!rc.contains("SocksPort 9050"), "no TCP SOCKS port");
    }
}
