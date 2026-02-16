use super::env::ClientEnv;
use crate::socks5::Socks5Server;
use quinn::Endpoint;

pub async fn run_client() -> anyhow::Result<()> {
    use anyhow::Context;
    use super::{write_pt_message, PT_VERSION};

    let env = ClientEnv::from_env()
        .context("Failed to load client environment")?;

    let ca_cert_hex = env.transport_options
        .get("quictor")
        .and_then(|opts| opts.get("ca-cert"))
        .context("Missing ca-cert in TOR_PT_CLIENT_TRANSPORT_OPTIONS (quictor:ca-cert=<hex>)")?;

    let client_config = crate::config::configure_client(ca_cert_hex)
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

        let quic_server_addr = socks_conn.target_addr();
        let socks_stream = socks_conn.into_stream();

        let endpoint_clone = endpoint.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_socks_connection(
                endpoint_clone,
                socks_stream,
                quic_server_addr,
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
    quic_recv: quinn::RecvStream,
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
