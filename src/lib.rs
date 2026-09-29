//! Mjolnir: move large files over N parallel TCP connections, each chunk
//! sealed on its own with an AEAD, peers authenticated by static keys with
//! Noise IK. The protocol is specified in `docs/PROTOCOL.md`.
//!
//! [`send`] and [`Receiver::run`] block until the transfer ends; run them on
//! a thread and watch the shared [`Progress`]. [`tunnel`] forwards TCP ports
//! over the same authenticated sessions and runs on tokio.

mod benchmode;
pub mod bitset;
pub mod crypto;
pub mod filemap;
pub mod fsops;
pub mod keys;
pub mod manifest;
pub mod names;
mod net;
mod pool;
pub mod posio;
pub mod printable;
pub mod progress;
pub mod recv;
mod schedule;
pub mod send;
pub mod tunnel;
pub mod web;
pub mod wire;

pub use crypto::Cipher;
pub use keys::{
    AuthorizedKey, PrivateKey, PublicKey, default_key_path, load_authorized_entries,
    load_authorized_keys, parse_authorized_entries, parse_authorized_keys,
};
pub use manifest::parse_size;
pub use progress::{Cancelled, Phase, PhaseTimes, Progress, ProgressSnapshot};
pub use recv::{Receiver, RecvConfig, RecvReport, recv};
pub use send::{SendConfig, SendReport, send};
