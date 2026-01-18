pub mod env;
pub mod client;
pub mod server;

pub const PT_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq)]
pub enum PtMode {
    Client,
    Server,
}

pub fn detect_mode() -> anyhow::Result<PtMode> {
    use anyhow::bail;

    if std::env::var("TOR_PT_CLIENT_TRANSPORTS").is_ok() {
        return Ok(PtMode::Client);
    }

    if std::env::var("TOR_PT_SERVER_TRANSPORTS").is_ok() {
        return Ok(PtMode::Server);
    }

    bail!("Neither TOR_PT_CLIENT_TRANSPORTS nor TOR_PT_SERVER_TRANSPORTS is set")
}

pub fn write_pt_message(message: &str) -> anyhow::Result<()> {
    use std::io::Write;
    
    println!("{}", message);
    std::io::stdout().flush()?;
    
    Ok(())
}
