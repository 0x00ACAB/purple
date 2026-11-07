//! The torrc purple runs tor with: a client only, with its SOCKS socket in the directory
//! purple-subspace sees and its control socket in one only purple-cloak sees, and a circuit
//! per SOCKS username.

use crate::sandbox::{TOR_CONTROL, TOR_COOKIE, TOR_DATA_DIR, TOR_SOCKS};

pub(crate) fn torrc() -> String {
    format!(
        "DataDirectory {TOR_DATA_DIR}\n\
         SocksPort unix:{TOR_SOCKS} IsolateSOCKSAuth OnionTrafficOnly\n\
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
        assert!(rc.contains("ControlPort unix:/run/torctl/control.sock"));
        assert!(rc.contains("CookieAuthentication 1"));
        assert!(rc.contains("CookieAuthFile /run/torctl/control.cookie"));
        assert!(rc.contains("DataDirectory /var/lib/tor"));
        assert!(rc.contains("ClientOnly 1"));
        assert!(!rc.contains("SocksPort 9050"), "no TCP SOCKS port");
        assert!(
            rc.contains("SocksPort unix:/run/tor/socks.sock IsolateSOCKSAuth OnionTrafficOnly"),
            "nothing but onion services through the SOCKS port"
        );
    }
}
