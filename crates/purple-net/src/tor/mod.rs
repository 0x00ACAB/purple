//! The Tor transport: purple-net reaches the store's onion service through tor's SOCKS
//! socket, with a circuit per stream, and drives tor's bridges through its control socket.

pub mod socks;
