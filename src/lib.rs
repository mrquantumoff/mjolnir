//! Gorynych: move large files over N parallel TCP connections, each chunk
//! sealed on its own with an AEAD, peers authenticated by static keys with
//! Noise IK. The protocol is specified in `docs/PROTOCOL.md`.

pub mod bitset;
pub mod crypto;
pub mod keys;
pub mod manifest;
pub mod posio;
pub mod progress;
pub mod wire;

pub use crypto::Cipher;
pub use keys::{
    PrivateKey, PublicKey, default_key_path, load_authorized_keys, parse_authorized_keys,
};
pub use manifest::parse_size;
pub use progress::{Cancelled, Phase, Progress, ProgressSnapshot};
