//! The Tor transport: purple-subspace reaches the store's onion service through tor's SOCKS
//! socket, with a circuit per stream. tor's control port belongs to purple-cloak.

pub mod socks;
pub mod transport;
