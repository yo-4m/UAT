use anyhow::Result;
use quinn::{ClientConfig, ServerConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = CertificateDer::from(cert.cert);
    Ok((cert_der, key))
}

pub fn configure_server() -> Result<ServerConfig> {
    let (cert, key) = generate_self_signed_cert()?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    crypto.max_early_data_size = 0xffff_ffff;

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?
    ));

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());

    transport_config.stream_receive_window(VarInt::from_u32(1024 * 1024 * 2)); // 2MB
    transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 8)); // 8MB

    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));

    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

pub fn configure_client() -> Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    crypto.enable_early_data = true;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
    ));

    let mut transport_config = quinn::TransportConfig::default();

    transport_config.max_concurrent_bidi_streams(100_u32.into());
    transport_config.max_concurrent_uni_streams(100_u32.into());

    transport_config.stream_receive_window(VarInt::from_u32(1024 * 1024 * 2)); // 2MB
    transport_config.receive_window(VarInt::from_u32(1024 * 1024 * 8)); // 8MB

    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into()?));

    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
