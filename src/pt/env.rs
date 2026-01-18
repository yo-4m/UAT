use std::net::SocketAddr;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ClientEnv {
    pub transports: Vec<String>,
    pub state_location: String,
    pub proxy: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServerEnv {
    pub transports: Vec<String>,
    pub bind_addrs: HashMap<String, SocketAddr>,
    pub orport: SocketAddr,
    pub state_location: String,
}

impl ClientEnv {
    pub fn from_env() -> anyhow::Result<Self> {
        use anyhow::Context;

        let transports_str = std::env::var("TOR_PT_CLIENT_TRANSPORTS")
            .context("TOR_PT_CLIENT_TRANSPORTS not set")?;
        let transports: Vec<String> = transports_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let state_location = std::env::var("TOR_PT_STATE_LOCATION")
            .context("TOR_PT_STATE_LOCATION not set")?;

        let proxy = std::env::var("TOR_PT_PROXY").ok();

        Ok(ClientEnv {
            transports,
            state_location,
            proxy,
        })
    }
}

impl ServerEnv {
    pub fn from_env() -> anyhow::Result<Self> {
        use anyhow::Context;

        let transports_str = std::env::var("TOR_PT_SERVER_TRANSPORTS")
            .context("TOR_PT_SERVER_TRANSPORTS not set")?;
        let transports: Vec<String> = transports_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut bind_addrs = HashMap::new();
        let env_key = "TOR_PT_SERVER_BINDADDR";
        let bindaddr_str = std::env::var(env_key)
            .context(format!("{} not set", env_key))?;

        if let Some(dash_pos) = bindaddr_str.find('-') {
            let transport_name = &bindaddr_str[..dash_pos];
            let addr_str = &bindaddr_str[dash_pos + 1..];

            let addr: SocketAddr = addr_str.parse()
                .context(format!("Invalid bind address: {}", addr_str))?;
            bind_addrs.insert(transport_name.to_string(), addr);
        } else {
            anyhow::bail!("Invalid TOR_PT_SERVER_BINDADDR format: {}", bindaddr_str);
        }

        let orport_str = std::env::var("TOR_PT_ORPORT")
            .context("TOR_PT_ORPORT not set")?;
        let orport: SocketAddr = orport_str.parse()
            .context(format!("Invalid ORPort address: {}", orport_str))?;

        let state_location = std::env::var("TOR_PT_STATE_LOCATION")
            .context("TOR_PT_STATE_LOCATION not set")?;

        Ok(ServerEnv {
            transports,
            bind_addrs,
            orport,
            state_location,
        })
    }
}
