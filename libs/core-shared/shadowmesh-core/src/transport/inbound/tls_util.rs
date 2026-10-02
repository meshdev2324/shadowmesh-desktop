//! Server-side TLS acceptor construction for inbounds that terminate TLS on
//! the edge (Trojan-GFW requires TLS on the wire). Loads a PEM cert/key pair
//! into a rustls `TlsAcceptor`.

use anyhow::{anyhow, Context, Result};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Builds a TLS server acceptor from a PEM certificate/key pair.
///
/// No client auth (Trojan authenticates at the application layer with a
/// constant-time SHA-224 digest comparison). The ring crypto provider is
/// pinned explicitly so provider selection never depends on process-global
/// install state or on which crate enabled which rustls feature.
pub fn build_server_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("open TLS certificate file '{cert_path}'"))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parse TLS certificates from '{cert_path}'"))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in '{cert_path}'"));
    }

    let key_file =
        std::fs::File::open(key_path).with_context(|| format!("open TLS key file '{key_path}'"))?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
        .with_context(|| format!("parse TLS private key from '{key_path}'"))?
        .ok_or_else(|| anyhow!("no private key found in '{key_path}'"))?;

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("select rustls protocol versions")?;

    let config = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate/key pair")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_cert_file() {
        let r = build_server_acceptor("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(r.is_err(), "missing cert file must be a hard error");
    }
}
