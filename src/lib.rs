pub mod config;
pub mod pt;
pub mod socks5;

pub use config::{configure_client, configure_server};

/// QuicTor Pluggable Transport version
pub const VERSION: &str = "0.1.0";

/// Default QUIC port for QuicTor
pub const DEFAULT_PORT: u16 = 4433;
