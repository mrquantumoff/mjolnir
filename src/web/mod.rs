//! Local web control plane for managing transfers, served by `gorynych serve`.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::keys::PrivateKey;

pub struct ServeConfig {
    pub listen: SocketAddr,
    pub key: PrivateKey,
    pub key_path: PathBuf,
    pub open_browser: bool,
}

pub fn serve(cfg: ServeConfig) -> anyhow::Result<()> {
    let _ = cfg;
    anyhow::bail!("the web UI is not implemented yet")
}
