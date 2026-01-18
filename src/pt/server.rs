use super::env::ServerEnv;
use quinn::Endpoint;
use std::net::SocketAddr;

pub async fn run_server() -> anyhow::Result<()> {
    use anyhow::Context;
    use super::{write_pt_message, PT_VERSION};

    let env = ServerEnv::from_env()
        .context("Failed to load server environment")?;

    let server_config = crate::config::configure_server()
        .context("Failed to configure QUIC server")?;

    let bind_addr = env.bind_addrs.get("quictor")
        .context("No bind address for 'quictor' transport")?;

    let endpoint = Endpoint::server(server_config, *bind_addr)
        .context("Failed to create QUIC endpoint")?;

    let orport = env.orport;

    write_pt_message(&format!("VERSION {}", PT_VERSION))?;
    write_pt_message(&format!("SMETHOD quictor {}", bind_addr))?;
    write_pt_message("SMETHODS DONE")?;

    loop {
        let incoming = match endpoint.accept().await {
            Some(incoming) => incoming,
            None => {
                tracing::warn!("Endpoint closed");
                break;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, orport).await {
                tracing::error!("Failed to handle connection: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    orport: SocketAddr,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let connection = incoming.await
        .context("Failed to accept QUIC connection")?;

    tracing::info!("New QUIC connection from {}", connection.remote_address());

    loop {
        tracing::debug!("Waiting for bidirectional stream...");
        let stream = match connection.accept_bi().await {
            Ok(stream) => {
                tracing::info!("Accepted bidirectional stream");
                stream
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                tracing::debug!("Connection closed by client");
                break;
            }
            Err(quinn::ConnectionError::TimedOut) => {
                tracing::warn!("Connection timed out waiting for stream");
                break;
            }
            Err(e) => {
                tracing::error!("Failed to accept stream: {}", e);
                break;
            }
        };

        let (send, recv) = stream;

        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, orport).await {
                tracing::error!("Failed to handle stream: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_stream(
    quic_send: quinn::SendStream,
    quic_recv: quinn::RecvStream,
    orport: SocketAddr,
) -> anyhow::Result<()> {
    use anyhow::Context;

    let mut tcp_stream = tokio::net::TcpStream::connect(orport)
        .await
        .context("Failed to connect to ORPort")?;

    tracing::debug!("Connected to ORPort at {}", orport);

    let mut quic_stream = tokio::io::join(quic_recv, quic_send);

    let (to_tcp, to_quic) = tokio::io::copy_bidirectional(
        &mut tcp_stream,
        &mut quic_stream,
    )
    .await
    .context("Failed to copy bidirectional")?;

    tracing::debug!("Stream closed: {} bytes to TCP, {} bytes to QUIC", to_tcp, to_quic);

    Ok(())
}
