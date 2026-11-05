//! purple-torctl: the one process that talks to tor's control port. It watches tor's
//! bootstrap, switches bridges when tor can't connect, and tells core when the user has to
//! choose. purple-net, which parses what the store sends, never sees the control port.

pub mod bridges;
pub mod control;
pub mod driver;
pub mod fallback;
