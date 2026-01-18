mod pt;
mod socks5;
mod config;

use anyhow::Result;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!("QuicTor Pluggable Transport starting...");

    let mode = match pt::detect_mode() {
        Ok(mode) => mode,
        Err(e) => {
            error!("Failed to detect PT mode: {}", e);
            return Err(e);
        }
    };

    info!("Running in {:?} mode", mode);

    let result = match mode {
        pt::PtMode::Client => {
            info!("Starting PT Client...");
            pt::client::run_client().await
        }
        pt::PtMode::Server => {
            info!("Starting PT Server...");
            pt::server::run_server().await
        }
    };

    if let Err(e) = result {
        error!("PT execution failed: {}", e);
        return Err(e);
    }

    Ok(())
}
