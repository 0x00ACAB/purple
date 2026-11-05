//! The Tor transport: purple-net reaches the store's onion service through tor's SOCKS
//! socket, with a circuit per stream, and drives tor's bridges through its control socket.

pub mod control;
pub mod fallback;
pub mod socks;
pub mod transport;
