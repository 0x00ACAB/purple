//! purple-memory-alpha: keeps write-once boxes on disk for purple clients. It only ever
//! sees box addresses, and reaches clients through a Tor onion service (or, for direct
//! mode, a Noise port), so it doesn't learn their IP addresses either.

pub mod disk;
