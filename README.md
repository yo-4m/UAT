# QuicTor PT

A Pluggable Transport (PT) implementation for Tor that uses QUIC protocol to tunnel Tor traffic.

## Overview

QuicTor PT is a proof-of-concept Pluggable Transport that encapsulates Tor traffic within QUIC connections. This can help bypass censorship by making Tor traffic appear as regular QUIC/HTTP3 traffic.

## Features

- QUIC-based transport using the Quinn library
- Implements Tor's Pluggable Transport specification
- Client mode: SOCKS5 proxy that tunnels traffic over QUIC
- Server mode: QUIC server that forwards traffic to Tor ORPort
- Docker-based development environment for testing

## Requirements

- Rust 1.70+
- Docker and Docker Compose
- Tor

## Setup

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yo-4m/UAT.git
cd UAT
```

2. Run the setup script:
```bash
./setup.sh
```

3. Start the containers:
```bash
docker compose up --build
```

4. Test the connection:
```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

### Manual Build

```bash
cargo build
```

## Architecture

```
[Tor Client] <--SOCKS5--> [QuicTor Client] <--QUIC--> [QuicTor Server] <--TCP--> [Tor Bridge/Relay]
```

- **Client Mode**: Listens on a SOCKS5 port, accepts connections from Tor, and forwards them over QUIC to the server.
- **Server Mode**: Accepts QUIC connections and forwards the traffic to the local Tor ORPort.

## Project Structure

```
src/
├── main.rs          # Entry point
├── config.rs        # QUIC configuration
├── pt/
│   ├── mod.rs       # PT mode detection
│   ├── client.rs    # Client-side PT implementation
│   ├── server.rs    # Server-side PT implementation
│   └── env.rs       # Environment variable parsing
└── socks5/
    └── mod.rs       # SOCKS5 protocol implementation
```

## Important Notes

- **Development Stage**: This is a proof-of-concept implementation and is not ready for production use.
- **Self-Signed Certificates**: Currently uses self-signed certificates with verification disabled. For production use, proper certificate handling should be implemented.
- **Security**: The QUIC layer does not provide authentication beyond TLS. Tor's own encryption handles the actual security of the traffic.


## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.





## Disclaimer

The developers assume no responsibility whatsoever for any damages arising from the use of this software.

This software is provided for academic and technical research aimed at privacy protection and the advancement of the Tor Project. It does not endorse or support its use for illegal activities.
