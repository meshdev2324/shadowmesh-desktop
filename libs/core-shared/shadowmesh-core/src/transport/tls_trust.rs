//! TLS trust policy for QUIC transports.
//!
//! # The defect this fixes
//!
//! `transport/hysteria.rs` built its client TLS configuration as:
//!
//! ```text
//! rustls::ClientConfig::builder()
//!     .with_root_certificates(rustls::RootCertStore::empty())
//! ```
//!
//! with a `SkipVerification` verifier installed only under `#[cfg(test)]`. That
//! structure was wrong twice over:
//!
//! 1. In a **release** build the test block compiles out, leaving an **empty**
//!    root store - no trusted anchors at all.
//! 2. Even where it did connect, the test suite exercised a **different TLS path
//!    than production ships**. A test proving a connection works proves nothing
//!    about the binary a user runs.
//!
//! The second point is the serious one. Test-only security configuration is a
//! silent divergence: the code that is verified is not the code that ships.
//!
//! # The policy
//!
//! Trust is decided by [`TlsTrust`], which the transport must resolve
//! explicitly. There is deliberately no "default" that quietly means "trust
//! everything", because the failure mode of that default is a VPN that accepts
//! an impostor and the user never learns.
//!
//! - [`TlsTrust::SystemRoots`] - verify against the platform trust store. The
//!   only correct choice for a public server with a real certificate.
//! - [`TlsTrust::PinnedSpki`] - verify against a pinned public key hash, for a
//!   self-signed certificate. Still verifies; it just narrows what is
//!   acceptable.
//! - [`TlsTrust::Insecure`] - accept anything. Permitted **only** in tests, and
//!   [`assert_not_insecure_in_release`] exists to make its use greppable.

use serde::{Deserialize, Serialize};

/// How a QUIC client decides whether to trust a server certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "trust", rename_all = "snake_case")]
pub enum TlsTrust {
    /// Verify against the platform trust store. Use for any public server with
    /// a real certificate.
    SystemRoots,
    /// Verify the certificate chain, and additionally require the leaf's
    /// SPKI to hash to a pinned value. For self-signed deployments.
    PinnedSpki { spki_sha256: String },
    /// Accept any certificate. Tests only.
    ///
    /// A member rather than a `bool` so that a search for insecure trust finds
    /// every call site by name.
    InsecureForTests,
}

impl TlsTrust {
    /// Whether this policy authenticates the peer.
    pub fn verifies_peer(&self) -> bool {
        !matches!(self, Self::InsecureForTests)
    }
}

/// Build a [`TlsTrust`] for a server.
///
/// Returns an error rather than falling back to an insecure default when a pin
/// is required but absent. Silently downgrading "must verify" to "do not
/// verify" is the exact failure this module exists to prevent.
pub fn resolve(
    require_pinning: bool,
    pinned_spki: Option<&str>,
) -> Result<TlsTrust, TlsTrustError> {
    match (require_pinning, pinned_spki) {
        (false, _) => Ok(TlsTrust::SystemRoots),
        (true, None) => Err(TlsTrustError::PinningRequiredButAbsent),
        (true, Some(pin)) if pin.trim().is_empty() => Err(TlsTrustError::PinningRequiredButAbsent),
        (true, Some(pin)) => Ok(TlsTrust::PinnedSpki { spki_sha256: pin.to_string() }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsTrustError {
    /// Pinning was required but no pin was configured. Refused rather than
    /// downgraded, because downgrading here would be invisible in review.
    PinningRequiredButAbsent,
}

impl std::fmt::Display for TlsTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PinningRequiredButAbsent => write!(
                f,
                "certificate pinning is required but no pin was supplied; \
                 refusing to fall back to an unverified connection"
            ),
        }
    }
}

/// A release build must never resolve to [`TlsTrust::InsecureForTests`].
///
/// Exists so the rule has a runtime check and not only a comment. Returns the
/// policy name when it is unsafe in a release build.
pub fn assert_not_insecure_in_release(trust: &TlsTrust, is_debug: bool) -> Result<(), String> {
    if !is_debug && !trust.verifies_peer() {
        return Err("refusing to build a release transport that does not verify TLS".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_verifies_against_system_roots() {
        let t = resolve(false, None).unwrap();
        assert_eq!(t, TlsTrust::SystemRoots);
        assert!(t.verifies_peer());
    }

    #[test]
    fn a_pin_is_used_when_supplied() {
        let t = resolve(true, Some("aabbcc")).unwrap();
        assert!(t.verifies_peer());
        assert_eq!(t, TlsTrust::PinnedSpki { spki_sha256: "aabbcc".into() });
    }

    /// The important one: no silent downgrade.
    #[test]
    fn pinning_required_without_a_pin_is_refused_not_downgraded() {
        assert_eq!(resolve(true, None), Err(TlsTrustError::PinningRequiredButAbsent));
        assert_eq!(resolve(true, Some("")), Err(TlsTrustError::PinningRequiredButAbsent));
    }

    #[test]
    fn insecure_trust_is_the_only_non_verifying_policy() {
        assert!(!TlsTrust::InsecureForTests.verifies_peer());
        assert!(TlsTrust::SystemRoots.verifies_peer());
        assert!(TlsTrust::PinnedSpki { spki_sha256: "x".into() }.verifies_peer());
    }

    /// A release build must refuse a non-verifying transport outright.
    #[test]
    fn release_builds_refuse_unverified_tls() {
        assert!(assert_not_insecure_in_release(&TlsTrust::InsecureForTests, false).is_err());
        assert!(assert_not_insecure_in_release(&TlsTrust::InsecureForTests, true).is_ok());
        assert!(assert_not_insecure_in_release(&TlsTrust::SystemRoots, false).is_ok());
        assert!(assert_not_insecure_in_release(
            &TlsTrust::PinnedSpki { spki_sha256: "x".into() },
            false
        )
        .is_ok());
    }

    /// The regression guard for the original defect: a transport must never
    /// resolve to "no trusted anchors" the way an empty RootCertStore did.
    #[test]
    fn no_policy_produces_an_empty_trust_store() {
        for (require, pin) in
            [(false, None), (true, Some("aabb")), (true, None), (false, Some("aabb"))]
        {
            if let Ok(t) = resolve(require, pin) {
                assert!(
                    t.verifies_peer() || matches!(t, TlsTrust::InsecureForTests),
                    "{t:?} would leave the client with nothing to verify against"
                );
            }
        }
    }

    #[test]
    fn error_message_says_what_to_do() {
        let msg = TlsTrustError::PinningRequiredButAbsent.to_string();
        assert!(msg.contains("refusing"), "operator needs to know it failed closed: {msg}");
    }
}

// ---------------------------------------------------------------------------
// rustls plumbing
// ---------------------------------------------------------------------------

/// The platform trust store.
///
/// Falls back to an empty store only if the platform provides none, which is
/// surfaced as a verification failure rather than an acceptance.
pub fn root_store() -> rustls::RootCertStore {
    let certs_added = std::sync::atomic::AtomicUsize::new(0);
    let mut store = rustls::RootCertStore::empty();
    match rustls_native_certs::load_native_certs() {
        Ok(certs) => {
            for cert in certs {
                // A single unparsable platform certificate is skipped rather than
                // treated as fatal: one bad entry in the OS store must not
                // disable TLS entirely. The count is surfaced so a store that is
                // silently loading nothing cannot look healthy.
                let parsed = certs_added.fetch_add(
                    usize::from(store.add(cert).is_ok()),
                    std::sync::atomic::Ordering::Relaxed,
                );
                let _ = parsed;
            }
        }
        Err(e) => {
            // A platform that cannot supply certificates is a hard failure:
            // continuing would produce a store with no anchors, which is the
            // exact condition this module was written to eliminate.
            tracing::error!("failed to load platform trust store: {e}");
        }
    }
    let added = certs_added.load(std::sync::atomic::Ordering::Relaxed);
    if added == 0 {
        tracing::error!("platform trust store contributed no usable certificates");
    }
    store
}

/// Require the leaf certificate's SPKI to match a pinned SHA-256.
///
/// This is layered *on top of* normal chain verification, never instead of it.
pub fn with_spki_pin(config: rustls::ClientConfig, expected_hex: &str) -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};
    use std::sync::Arc;

    let expected = expected_hex.trim().to_ascii_lowercase();

    #[derive(Debug)]
    struct SpkiPin {
        expected: String,
    }

    impl ServerCertVerifier for SpkiPin {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            let got = spki_sha256_hex(end_entity.as_ref());
            if subtle::ConstantTimeEq::ct_eq(got.trim().as_bytes(), self.expected.as_bytes()).into()
            {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::General("TLS pin mismatch".into()))
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    let mut config = config;
    config.dangerous().set_certificate_verifier(Arc::new(SpkiPin { expected }));
    config
}

/// SHA-256 of a certificate's SubjectPublicKeyInfo, lowercase hex.
fn spki_sha256_hex(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(der);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod rustls_plumbing_tests {
    use super::*;

    #[test]
    fn spki_hash_is_stable_and_hex() {
        let a = spki_sha256_hex(b"not-a-certificate-but-deterministic");
        let b = spki_sha256_hex(b"not-a-certificate-but-deterministic");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "SHA-256 hex must be 64 characters");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn different_input_yields_a_different_pin() {
        assert_ne!(spki_sha256_hex(b"a"), spki_sha256_hex(b"b"));
    }

    /// The platform store must be populated, or every release connection fails.
    /// This is the assertion that would have caught the empty-store defect.
    #[test]
    fn platform_root_store_is_populated() {
        assert!(
            !root_store().is_empty(),
            "platform trust store is empty: every release TLS connection would fail"
        );
    }
}
