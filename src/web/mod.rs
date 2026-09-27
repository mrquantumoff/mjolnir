//! Local web control plane for managing transfers, served by `gorynych serve`.

use std::net::SocketAddr;

use crate::keys::PrivateKey;

pub struct ServeConfig {
    pub listen: SocketAddr,
    pub key: PrivateKey,
    pub open_browser: bool,
}

pub fn serve(cfg: ServeConfig) -> anyhow::Result<()> {
    let _ = cfg;
    anyhow::bail!("the web UI is not implemented yet")
}
