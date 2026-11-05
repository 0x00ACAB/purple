//! purple-core library: invites, 1:1 sessions, queues, and the messenger that ties them
//! together.

mod codec;
pub mod content;
pub mod credential;
pub mod fragment;
pub mod group;
pub mod invite;
pub mod messenger;
pub mod mls;
pub mod queue;
pub mod session;
mod signal_store;
pub mod tpm;
pub mod vault;
