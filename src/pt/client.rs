use super::env::ClientEnv;
use crate::socks5::Socks5Server;
use quinn::Endpoint;

pub async fn run_client() -> anyhow::Result<()> {
    use anyhow::Context;
    use super::{write_pt_message, PT_VERSION};

    let env = ClientEnv::from_env()
        .context("Failed to load client environment")?;

    let client_config = crate::config::configure_client()
        .context("Failed to configure QUIC client")?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)
        .context("Failed to create QUIC endpoint")?;
    endpoint.set_default_client_config(client_config);

    let socks_server = Socks5Server::bind("127.0.0.1:0".parse()?)
        .await
        .context("Failed to bind SOCKS5 server")?;

    let socks_addr = socks_server.local_addr()
        .context("Failed to get SOCKS5 server address")?;

    write_pt_message(&format!("VERSION {}", PT_VERSION))?;
    write_pt_message(&format!("CMETHOD quictor socks5 {}", socks_addr))?;
    write_pt_message("CMETHODS DONE")?;

    loop {
        let socks_conn = match socks_server.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!("Failed to accept SOCKS5 connection: {}", e);
                continue;
            }
        };

        let target_addr = socks_conn.target_addr();
        let socks_stream = socks_conn.into_stream();

        let quic_server_addr_str = std::env::var("QUIC_SERVER_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:4433".to_string());

        let endpoint_clone = endpoint.clone();

        tokio::spawn(async move {
            let quic_server_addr = match resolve_bridge_address(&quic_server_addr_str).await {
                Ok(addr) => addr,
                Err(e) => {
                    tracing::error!("Failed to resolve bridge address '{}': {}", quic_server_addr_str, e);
                    return;
                }
            };

            if let Err(e) = handle_socks_connection(
                endpoint_clone,
                socks_stream,
                quic_server_addr,
                target_addr,
            ).await {
                tracing::error!("Failed to handle SOCKS5 connection: {}", e);
            }
        });
    }
}

async fn handle_socks_connection(
    endpoint: Endpoint,
    socks_stream: tokio::net::TcpStream,
    quic_server_addr: std::net::SocketAddr,
    _target_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let connection = endpoint
        .connect(quic_server_addr, "localhost")?
        .await
        .context("Failed to connect to QUIC server")?;

    let (quic_send, quic_recv) = connection
        .open_bi()
        .await
        .context("Failed to open bidirectional stream")?;

    bridge_socks5_to_quic(socks_stream, quic_send, quic_recv).await
}

async fn bridge_socks5_to_quic(
    mut socks_stream: tokio::net::TcpStream,
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    tracing::info!("Starting bidirectional copy between SOCKS5 and QUIC");

    let mut first_buf = vec![0u8; 1024];

    tokio::select! {
        result = socks_stream.read(&mut first_buf) => {
            match result {
                Ok(0) => {
                    tracing::warn!("SOCKS5 stream closed before sending data");
                    return Ok(());
                }
                Ok(n) => {
                    tracing::info!("Read {} bytes from SOCKS5, writing to QUIC", n);
                    quic_send.write_all(&first_buf[..n]).await
                        .context("Failed to write first chunk to QUIC")?;
                    quic_send.flush().await
                        .context("Failed to flush QUIC stream")?;
                    tracing::info!("Successfully wrote first chunk to QUIC");
                }
                Err(e) => {
                    return Err(anyhow::Error::from(e).context("Failed to read from SOCKS5"));
                }
            }
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
            tracing::warn!("Timeout waiting for first data from SOCKS5");
            return Err(anyhow::anyhow!("Timeout waiting for SOCKS5 data"));
        }
    }

    let mut quic_stream = tokio::io::join(quic_recv, quic_send);

    let (to_quic, to_socks) = tokio::io::copy_bidirectional(
        &mut socks_stream,
        &mut quic_stream,
    )
    .await
    .context("Failed to copy bidirectional")?;

    tracing::debug!("Connection closed: {} bytes to QUIC, {} bytes to SOCKS5", to_quic, to_socks);

    Ok(())
}

async fn resolve_bridge_address(addr_str: &str) -> anyhow::Result<std::net::SocketAddr> {
    use anyhow::Context;

    if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
        tracing::info!("Using bridge address: {}", addr);
        return Ok(addr);
    }

    tracing::info!("Resolving bridge hostname: {}", addr_str);

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr_str)
        .await
        .context(format!("Failed to resolve hostname: {}", addr_str))?
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("No addresses found for hostname: {}", addr_str);
    }

    for addr in &addrs {
        let ip = addr.ip();

        if ip.is_loopback() || ip.is_unspecified() {
            tracing::debug!("Skipping loopback/unspecified address: {}", addr);
            continue;
        }

        if let std::net::IpAddr::V4(ipv4) = ip {
            let octets = ipv4.octets();
            let is_private =
                octets[0] == 10 ||
                (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                (octets[0] == 192 && octets[1] == 168);

            if is_private {
                tracing::debug!("Skipping private IPv4 address: {}", addr);
                continue;
            }
        }

        tracing::info!("Resolved bridge address to: {}", addr);
        return Ok(*addr);
    }
    
    for addr in &addrs {
        if !addr.ip().is_loopback() {
            tracing::warn!("Using non-public address (development mode?): {}", addr);
            return Ok(*addr);
        }
    }

    tracing::warn!("No valid public IP found, using first address: {}", addrs[0]);
    Ok(addrs[0])
}
