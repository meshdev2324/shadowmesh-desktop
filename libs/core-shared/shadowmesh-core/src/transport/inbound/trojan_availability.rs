//! Trojan inbound availability.
//!
//! # Why a domain is a hard requirement
//!
//! Trojan-GFW is defined as Trojan *over TLS*. Its whole censorship-resistance
//! argument is that the connection is indistinguishable from an ordinary HTTPS
//! session to a real website. Remove TLS and the protocol loses precisely the
//! property it exists to provide: a plaintext Trojan handshake begins with a
//! 56-character hex digest and the literal bytes `CMD`, which is a trivial
//! fingerprint for DPI.
//!
//! A domain is what makes a real certificate possible. Without one there is no
//! name to present, so there is no TLS identity, so there is nothing to serve.
//!
//! # The rule
//!
//! **Trojan is served if and only if a domain and a usable certificate are both
//! configured.** This module exists so that rule is decided in one place and
//! enforced by capability derivation, rather than being rediscovered each time
//! someone adds a listener. A node without a domain reports no Trojan
//! capability, and clients therefore never offer it.
//!
//! Turning Trojan off is consequently the default and requires no action: add no
//! domain and the protocol is absent from the advertised capability set. That is
//! the intended behaviour, not a gap to be filled later.

use serde::{Deserialize, Serialize};

/// Why an inbound is not serving. Deliberately specific: an operator has to be
/// able to tell "I forgot the domain" from "the certificate is wrong", because
/// the fix differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Unavailable {
    /// No domain configured. Trojan cannot serve without a TLS identity.
    NoDomain,
    /// A domain is present but no certificate was supplied.
    NoCertificate,
    /// A certificate was supplied but the key is missing, so TLS cannot start.
    NoPrivateKey,
    /// Certificate and key paths are set but the files are not readable.
    CertificateUnreadable { detail: String },
    /// The domain is syntactically not a hostname.
    InvalidDomain { domain: String },
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDomain => {
                write!(f, "no domain configured; Trojan needs one to present a TLS identity")
            }
            Self::NoCertificate => write!(f, "domain present but no TLS certificate configured"),
            Self::NoPrivateKey => write!(f, "certificate present but no private key configured"),
            Self::CertificateUnreadable { detail } => {
                write!(f, "TLS material unreadable: {detail}")
            }
            Self::InvalidDomain { domain } => write!(f, "'{domain}' is not a valid hostname"),
        }
    }
}

/// Whether a Trojan inbound can serve, and if not, why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Ready to serve. Carries no secrets.
    Available {
        domain: String,
        port: u16,
    },
    NotAvailable(Unavailable),
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// Inputs needed to decide Trojan availability.
///
/// `cert_path`/`key_path` are checked for existence rather than parsed, so this
/// stays cheap and free of any file I/O beyond a stat, and never touches
/// certificate material.
#[derive(Debug, Clone, Default)]
pub struct TrojanInputs<'a> {
    pub domain: Option<&'a str>,
    pub cert_path: Option<&'a str>,
    pub key_path: Option<&'a str>,
}

/// A hostname must be a dot-separated label sequence. No scheme, no port, no
/// path, no wildcard, no leading or trailing dot.
///
/// Wildcards are rejected deliberately: a certificate for `*.example.com` does
/// not cover `example.com`, so accepting one here would advertise a TLS identity
/// that fails at handshake time.
fn is_valid_hostname(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    if domain.starts_with('*') || domain.contains('*') {
        return false;
    }
    if domain.contains("://") || domain.contains('/') || domain.contains(':') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Decide whether a Trojan inbound can serve.
///
/// `stat_fn` is injected so the filesystem check is testable without fixtures.
pub fn evaluate<F>(inputs: TrojanInputs<'_>, stat_fn: F) -> Availability
where
    F: Fn(&str) -> bool,
{
    let Some(domain) = inputs.domain.map(str::trim).filter(|d| !d.is_empty()) else {
        return Availability::NotAvailable(Unavailable::NoDomain);
    };
    if !is_valid_hostname(domain) {
        return Availability::NotAvailable(Unavailable::InvalidDomain {
            domain: domain.to_string(),
        });
    }

    let Some(cert) = inputs.cert_path.filter(|p| !p.is_empty()) else {
        return Availability::NotAvailable(Unavailable::NoCertificate);
    };
    let Some(key) = inputs.key_path.filter(|p| !p.is_empty()) else {
        return Availability::NotAvailable(Unavailable::NoPrivateKey);
    };

    for (label, path) in [("certificate", cert), ("private key", key)] {
        if !stat_fn(path) {
            return Availability::NotAvailable(Unavailable::CertificateUnreadable {
                detail: format!("{label} not readable at configured path"),
            });
        }
    }

    Availability::Available { domain: domain.to_string(), port: 443 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_present(_: &str) -> bool {
        true
    }

    fn none_present(_: &str) -> bool {
        false
    }

    fn serve(domain: Option<&str>) -> Availability {
        evaluate(
            TrojanInputs { domain, cert_path: Some("/c.pem"), key_path: Some("/k.pem") },
            all_present,
        )
    }

    #[test]
    fn nothing_configured_is_off_by_default() {
        let a = evaluate(TrojanInputs::default(), all_present);
        assert!(!a.is_available());
        assert_eq!(a, Availability::NotAvailable(Unavailable::NoDomain));
    }

    /// The user's requirement: with no domain, Trojan is simply off. No error,
    /// no listener, no advertised capability.
    #[test]
    fn no_domain_means_off() {
        assert!(!serve(None).is_available());
        assert!(!serve(Some("")).is_available());
        assert!(!serve(Some("   ")).is_available());
    }

    #[test]
    fn domain_with_cert_and_key_is_available() {
        let a = serve(Some("vpn.example.com"));
        assert_eq!(a, Availability::Available { domain: "vpn.example.com".into(), port: 443 });
    }

    #[test]
    fn domain_without_certificate_is_not_available() {
        let a = evaluate(
            TrojanInputs {
                domain: Some("vpn.example.com"),
                cert_path: None,
                key_path: Some("/k.pem"),
            },
            all_present,
        );
        assert_eq!(a, Availability::NotAvailable(Unavailable::NoCertificate));
    }

    #[test]
    fn certificate_without_key_is_not_available() {
        let a = evaluate(
            TrojanInputs {
                domain: Some("vpn.example.com"),
                cert_path: Some("/c.pem"),
                key_path: None,
            },
            all_present,
        );
        assert_eq!(a, Availability::NotAvailable(Unavailable::NoPrivateKey));
    }

    #[test]
    fn unreadable_material_is_reported_precisely() {
        let a = evaluate(
            TrojanInputs {
                domain: Some("vpn.example.com"),
                cert_path: Some("/c.pem"),
                key_path: Some("/k.pem"),
            },
            none_present,
        );
        assert!(matches!(a, Availability::NotAvailable(Unavailable::CertificateUnreadable { .. })));
    }

    #[test]
    fn each_missing_piece_has_a_distinct_reason() {
        // An operator must be able to tell these apart; the fix differs.
        let none = serve(None);
        let no_cert = evaluate(
            TrojanInputs { domain: Some("a.example.com"), cert_path: None, key_path: None },
            all_present,
        );
        assert_ne!(none, no_cert);
    }

    #[test]
    fn rejects_uris_and_ports_in_the_domain() {
        for bad in ["https://vpn.example.com", "vpn.example.com:443", "vpn.example.com/path"] {
            assert_eq!(
                serve(Some(bad)),
                Availability::NotAvailable(Unavailable::InvalidDomain { domain: bad.into() }),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_malformed_hostnames() {
        for bad in ["", ".example.com", "example.com.", "a..b.com", "-lead.com", "trail-.com", "*"]
        {
            assert!(!serve(Some(bad)).is_available(), "{bad} should be rejected");
        }
    }

    /// A wildcard cert does not cover the apex, so accepting one would advertise
    /// a TLS identity that fails at handshake time.
    #[test]
    fn rejects_wildcards() {
        assert!(!serve(Some("*.example.com")).is_available());
    }

    #[test]
    fn accepts_hyphenated_and_multi_label_domains() {
        for good in ["vpn.example.com", "a-b.example.co.uk", "x.io", "sub.domain.example.com"] {
            assert!(serve(Some(good)).is_available(), "{good} should be accepted");
        }
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(!serve(Some("vpn.exämple.com")).is_available());
    }

    #[test]
    fn rejects_overlong_labels() {
        let long = "a".repeat(64);
        assert!(!serve(Some(&format!("{long}.example.com"))).is_available());
    }

    #[test]
    fn hostname_length_is_bounded() {
        let long = format!("{}.com", "a".repeat(250));
        assert!(!serve(Some(&long)).is_available());
    }

    #[test]
    fn unavailability_reasons_render_for_operators() {
        // These strings reach an operator's dashboard; each must say what to fix.
        for reason in [
            Unavailable::NoDomain,
            Unavailable::NoCertificate,
            Unavailable::NoPrivateKey,
            Unavailable::CertificateUnreadable { detail: "x".into() },
            Unavailable::InvalidDomain { domain: "x".into() },
        ] {
            let msg = reason.to_string();
            assert!(!msg.is_empty());
            assert!(msg.len() > 10, "reason too terse to act on: {msg}");
        }
    }
}
