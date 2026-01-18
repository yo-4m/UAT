use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;

pub struct Socks5Server {
    listener: TcpListener,
}

impl Socks5Server {
    pub async fn bind(addr: SocketAddr) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
    
        Ok(Socks5Server { listener })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn accept(&self) -> anyhow::Result<Socks5Connection> {
        let (stream, _addr) = self.listener.accept().await?;

        Socks5Connection::handshake(stream).await
    }
}

pub struct Socks5Connection {
    stream: TcpStream,
    target_addr: SocketAddr,
}

impl Socks5Connection {
    pub async fn handshake(mut stream: TcpStream) -> anyhow::Result<Self> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use anyhow::{Context, bail};

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await
            .context("Failed to read auth request header")?;

        if buf[0] != 0x05 {
            bail!("Unsupported SOCKS version: {}", buf[0]);
        }

        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await
            .context("Failed to read auth methods")?;

        stream.write_all(&[0x05, 0x00]).await
            .context("Failed to write auth response")?;

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await
            .context("Failed to read connection request header")?;

        if buf[0] != 0x05 {
            bail!("Unsupported SOCKS version: {}", buf[0]);
        }
        if buf[1] != 0x01 {
            bail!("Unsupported SOCKS command: {}", buf[1]);
        }

        let atyp = buf[3];
        let target_addr = match atyp {
            0x01 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await
                    .context("Failed to read IPv4 address")?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await
                    .context("Failed to read port")?;
                let port = u16::from_be_bytes(port_buf);

                SocketAddr::from((addr, port))
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await
                    .context("Failed to read domain length")?;
                let len = len_buf[0] as usize;

                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await
                    .context("Failed to read domain name")?;

                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await
                    .context("Failed to read port")?;
                let port = u16::from_be_bytes(port_buf);

                let domain_str = String::from_utf8(domain)
                    .context("Invalid UTF-8 in domain name")?;

                let addr = tokio::net::lookup_host(format!("{}:{}", domain_str, port))
                    .await
                    .context("Failed to resolve domain")?
                    .next()
                    .context("No addresses found for domain")?;

                addr
            }
            0x04 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await
                    .context("Failed to read IPv6 address")?;
                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await
                    .context("Failed to read port")?;
                let port = u16::from_be_bytes(port_buf);

                SocketAddr::from((addr, port))
            }
            _ => bail!("Unsupported address type: {}", atyp),
        };

        let response = [
            0x05, // VER
            0x00, // REP (success)
            0x00, // RSV
            0x01, // ATYP (IPv4)
            0, 0, 0, 0, // BND.ADDR (0.0.0.0)
            0, 0, // BND.PORT (0)
        ];
        stream.write_all(&response).await
            .context("Failed to write connection response")?;

        Ok(Socks5Connection {
            stream,
            target_addr,
        })
    }

    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    pub fn into_stream(self) -> TcpStream {
        self.stream
    }
}

pub async fn connect_via_socks5(
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
) -> anyhow::Result<TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use anyhow::{Context, bail};

    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .context("Failed to connect to SOCKS5 proxy")?;

    stream.write_all(&[0x05, 0x01, 0x00]).await
        .context("Failed to write auth request")?;

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await
        .context("Failed to read auth response")?;

    if buf[0] != 0x05 {
        bail!("Invalid SOCKS version in auth response: {}", buf[0]);
    }
    if buf[1] != 0x00 {
        bail!("SOCKS5 proxy requires authentication (method: {})", buf[1]);
    }

    let mut request = vec![0x05, 0x01, 0x00];

    match target_addr {
        SocketAddr::V4(addr) => {
            request.push(0x01); // ATYP: IPv4
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            request.push(0x04); // ATYP: IPv6
            request.extend_from_slice(&addr.ip().octets());
            request.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&request).await
        .context("Failed to write connection request")?;

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await
        .context("Failed to read connection response header")?;

    if buf[0] != 0x05 {
        bail!("Invalid SOCKS version in connection response: {}", buf[0]);
    }

    let rep = buf[1];
    if rep != 0x00 {
        bail!("SOCKS5 connection failed with reply code: {}", rep);
    }

    let atyp = buf[3];
    match atyp {
        0x01 => {
            let mut discard = [0u8; 6];
            stream.read_exact(&mut discard).await
                .context("Failed to read IPv4 bind address")?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await
                .context("Failed to read domain length")?;
            let len = len_buf[0] as usize;
            let mut discard = vec![0u8; len + 2];
            stream.read_exact(&mut discard).await
                .context("Failed to read domain bind address")?;
        }
        0x04 => {
            let mut discard = [0u8; 18];
            stream.read_exact(&mut discard).await
                .context("Failed to read IPv6 bind address")?;
        }
        _ => bail!("Unsupported address type in response: {}", atyp),
    }

    Ok(stream)
}
