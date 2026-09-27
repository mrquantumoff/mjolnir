//! Mjolnir: move large files over N parallel TCP connections, each chunk
//! sealed on its own with an AEAD, peers authenticated by static keys with
//! Noise IK. The protocol is specified in `docs/PROTOCOL.md`.
//!
//! [`send`] and [`Receiver::run`] block until the transfer ends; run them on
//! a thread and watch the shared [`Progress`].

pub mod bitset;
pub mod crypto;
pub mod keys;
pub mod manifest;
mod net;
pub mod posio;
mod pool;
pub mod progress;
pub mod recv;
pub mod send;
pub mod web;
pub mod wire;

pub use crypto::Cipher;
pub use keys::{
    PrivateKey, PublicKey, default_key_path, load_authorized_keys, parse_authorized_keys,
};
pub use manifest::parse_size;
pub use progress::{Cancelled, Phase, Progress, ProgressSnapshot};
pub use recv::{Receiver, RecvConfig, RecvReport, recv};
pub use send::{SendConfig, SendReport, send};
