//! The launcher's store config: where the store's onion service is, and optionally its
//! direct port and Noise key.

use std::io;
use std::net::SocketAddr;

const ONION_CHARS: usize = 56;

/// How to reach the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoreConfig {
    pub(crate) onion: String,
    pub(crate) port: u16,
    pub(crate) direct: Option<(SocketAddr, [u8; 32])>,
}

fn bad(why: &str) -> io::Error {
    io::Error::other(format!("store config: {why}"))
}

pub(crate) fn parse_store_config(text: &str) -> io::Result<StoreConfig> {
    let (mut onion, mut direct) = (None, None);
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["onion", address] => {
                let (host, port) = address
                    .rsplit_once(':')
                    .ok_or_else(|| bad("onion needs host:port"))?;
                let name = host
                    .strip_suffix(".onion")
                    .ok_or_else(|| bad("onion must be a .onion address"))?;
                let valid = name.len() == ONION_CHARS
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
                if !valid {
                    return Err(bad("that isn't a v3 onion address"));
                }
                onion = Some((
                    host.to_owned(),
                    port.parse().map_err(|_| bad("bad onion port"))?,
                ));
            }
            ["direct", addr, key] => {
                let addr: SocketAddr = addr
                    .parse()
                    .map_err(|_| bad("direct takes an IP address and port"))?;
                direct = Some((
                    addr,
                    parse_key(key).ok_or_else(|| bad("direct key must be 64 hex characters"))?,
                ));
            }
            _ => return Err(bad(&format!("don't understand {line:?}"))),
        }
    }
    let (onion, port) = onion.ok_or_else(|| bad("no onion line"))?;
    Ok(StoreConfig {
        onion,
        port,
        direct,
    })
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz2345.onion";

    #[test]
    fn parses_onion_and_direct() {
        let text = format!(
            "# store\nonion {ONION}:80\ndirect 192.0.2.10:4443 {}\n",
            "0f".repeat(32)
        );
        let c = parse_store_config(&text).unwrap();
        assert_eq!((c.onion.as_str(), c.port), (ONION, 80));
        assert_eq!(
            c.direct,
            Some(("192.0.2.10:4443".parse().unwrap(), [0x0f; 32]))
        );
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(parse_store_config("").is_err(), "onion is required");
        assert!(parse_store_config("onion example.com:80").is_err());
        assert!(
            parse_store_config(&format!("onion {ONION}")).is_err(),
            "port is required"
        );
        let bad_host = format!(
            "onion {ONION}:80\ndirect store.example:4443 {}",
            "0f".repeat(32)
        );
        assert!(
            parse_store_config(&bad_host).is_err(),
            "direct takes an IP literal"
        );
        assert!(parse_store_config(&format!("onion {ONION}:80\ndirect 192.0.2.1:1 abc")).is_err());
        assert!(parse_store_config(&format!("onion {ONION}:80\nbogus 1")).is_err());
    }
}
