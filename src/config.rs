use anyhow::{Context, Result};
use quinn::{ClientConfig, ServerConfig, VarInt};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("Hex string must have even length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

pub struct Certs {
    pub bridge_cert: CertificateDer<'static>,
    pub bridge_key: PrivateKeyDer<'static>,
    pub ca_cert_hex: String,
}

fn generate_ca(key: &KeyPair) -> Result<rcgen::Certificate> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(rcgen::DnType::CommonName, "QuicTor PT CA");
    Ok(params.self_signed(key)?)
}

fn generate_bridge(
    key: &KeyPair,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> Result<rcgen::Certificate> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .context("Failed to create bridge cert params")?;
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    Ok(params.signed_by(key, ca_cert, ca_key)?)
}

pub fn load_or_create_certs(state_dir: &str) -> Result<Certs> {
    let ca_cert_path = Path::new(state_dir).join("ca_cert.der");
    let ca_key_path = Path::new(state_dir).join("ca_key.der");
    let bridge_cert_path = Path::new(state_dir).join("bridge_cert.der");
    let bridge_key_path = Path::new(state_dir).join("bridge_key.der");

    if ca_cert_path.exists()
        && ca_key_path.exists()
        && bridge_cert_path.exists()
        && bridge_key_path.exists()
    {
        let ca_cert_bytes = std::fs::read(&ca_cert_path)?;
        let bridge_cert_bytes = std::fs::read(&bridge_cert_path)?;
        let bridge_key_bytes = std::fs::read(&bridge_key_path)?;

        return Ok(Certs {
            bridge_cert: CertificateDer::from(bridge_cert_bytes),
            bridge_key: PrivateKeyDer::Pkcs8(bridge_key_bytes.into()),
            ca_cert_hex: to_hex(&ca_cert_bytes),
        });
    }

    std::fs::create_dir_all(state_dir)?;

    let ca_key = KeyPair::generate()?;
    let ca_cert = generate_ca(&ca_key)?;
    let ca_cert_bytes = ca_cert.der().as_ref().to_vec();

    let bridge_key = KeyPair::generate()?;
    let bridge_cert = generate_bridge(&bridge_key, &ca_cert, &ca_key)?;
    let bridge_cert_bytes = bridge_cert.der().as_ref().to_vec();

    std::fs::write(&ca_cert_path, &ca_cert_bytes)?;
    std::fs::write(&ca_key_path, ca_key.serialize_der())?;
    std::fs::write(&bridge_cert_path, &bridge_cert_bytes)?;
    std::fs::write(&bridge_key_path, bridge_key.serialize_der())?;

    Ok(Certs {
        bridge_cert: CertificateDer::from(bridge_cert_bytes),
        bridge_key: PrivateKeyDer::Pkcs8(bridge_key.serialize_der().into()),
        ca_cert_hex: to_hex(&ca_cert_bytes),
    })
}

pub fn configure_server(state_dir: &str) -> Result<(ServerConfig, String)> {
    let certs = load_or_create_certs(state_dir)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certs.bridge_cert], certs.bridge_key)?;

    crypto.max_early_data_size = 0xffff_ffff;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());
    transport_config.stream_receive_window(VarInt::from_u32(1024 * 1024 * 2));
    transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 8));
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));

    server_config.transport_config(Arc::new(transport_config));

    Ok((server_config, certs.ca_cert_hex))
}

pub fn configure_client(ca_cert_hex: &str) -> Result<ClientConfig> {
    let ca_cert_bytes = from_hex(ca_cert_hex)
        .context("Failed to decode ca-cert hex")?;
    let ca_cert_der = CertificateDer::from(ca_cert_bytes);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert_der)?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    crypto.enable_early_data = true;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());
    transport_config.stream_receive_window(VarInt::from_u32(1024 * 1024 * 2));
    transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 8));
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));

    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}
