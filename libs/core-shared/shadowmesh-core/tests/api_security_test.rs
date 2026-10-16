use mockito::Server;
use shadowmesh_core::ApiClient;

#[tokio::test]
async fn test_api_client_mandatory_headers() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let client = ApiClient::new(url).unwrap();

    client.set_device_id("test-device-id-1234567890".to_string());
    client.set_auth_token(Some("test-token".to_string()));

    let mock = server
        .mock("GET", "/api/v1/nodes")
        .match_header("Authorization", "Bearer test-token")
        .match_header("X-Shadow-Device-ID", "test-device-id-1234567890")
        .with_status(200)
        .with_body("[]")
        .create_async()
        .await;

    let _ = client.get_nodes_async().await;
    mock.assert_async().await;
}

#[tokio::test]
async fn test_report_compromised_payload() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let client = ApiClient::new(url).unwrap();

    let device_id = "test-device-id-1234567890";
    let reason = "test-reason";

    let mock = server
        .mock("POST", "/api/v1/auth/report-compromised")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "device_id": device_id,
            "reason": reason
        })))
        .with_status(200)
        .create_async()
        .await;

    let _ = client.report_compromised_async(device_id.to_string(), reason.to_string()).await;
    mock.assert_async().await;
}

// ── C6 / RFC-011 §4.2 — the update manifest must be signed ───────────────────
//
// RFC-011 §4.2 specifies "a signed manifest (minisign/ed25519)". The fetch was a
// plain `GET` with no verification at all, and the result is not inert:
// `KillSwitchManager::check_remote` writes `manifest.flags` straight into the
// kill switch's feature-flag table, which gates `mfa_auth`, `biometric_lock`,
// `remote_panic_wipe` and `ebpf_monitoring`. So an unsigned body is an
// unauthenticated write into client security state.

use shadowmesh_core::api_client::{MANIFEST_PUBLIC_KEY_ENV, MANIFEST_SIGNATURE_HEADER};

/// A test Ed25519 keypair. Generated from a fixed test seed at run time — never
/// a literal, and never a key that exists anywhere but this process.
fn test_signing_key(seed_byte: u8) -> ([u8; 32], Vec<u8>) {
    use ring::signature::KeyPair;
    let seed = [seed_byte; 32];
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .expect("ring builds an Ed25519 keypair from a 32-byte seed");
    (seed, pair.public_key().as_ref().to_vec())
}

fn sign(seed: &[u8; 32], message: &[u8]) -> String {
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .expect("ring builds an Ed25519 keypair from a 32-byte seed");
    hex::encode(pair.sign(message).as_ref())
}

/// Set the manifest verification key for the duration of one test and put the
/// previous environment back afterwards.
struct PubKeyGuard(Option<String>);

impl PubKeyGuard {
    fn set(hex_key: Option<&str>) -> Self {
        let prior = std::env::var(MANIFEST_PUBLIC_KEY_ENV).ok();
        // SAFETY: `nextest` runs each test in its own process, and the `Drop`
        // below restores the value for a plain `cargo test` run.
        unsafe {
            match hex_key {
                Some(value) => std::env::set_var(MANIFEST_PUBLIC_KEY_ENV, value),
                None => std::env::remove_var(MANIFEST_PUBLIC_KEY_ENV),
            }
        }
        Self(prior)
    }
}

impl Drop for PubKeyGuard {
    fn drop(&mut self) {
        // SAFETY: as above.
        unsafe {
            match self.0.as_deref() {
                Some(previous) => std::env::set_var(MANIFEST_PUBLIC_KEY_ENV, previous),
                None => std::env::remove_var(MANIFEST_PUBLIC_KEY_ENV),
            }
        }
    }
}

const MANIFEST_BODY: &str = r#"{"flags":{"mfa_auth":true,"remote_panic_wipe":true},"min_client_version":"0.1.0","timestamp":1}"#;

async fn manifest_server(
    server: &mut Server,
    body: &str,
    signature: Option<&str>,
) -> mockito::Mock {
    let mut mock = server.mock("GET", "/api/v1/security/manifest").with_status(200).with_body(body);
    if let Some(sig) = signature {
        // A RESPONSE header — the signature travels beside the body, not
        // inside it. `match_header` here would assert on the *request* and the
        // mock would answer 501, which would make every refusal test below
        // pass for the wrong reason.
        mock = mock.with_header(MANIFEST_SIGNATURE_HEADER, sig);
    }
    mock.create_async().await
}

/// No signature at all. The body is perfectly well-formed JSON and would be
/// accepted today — that is the defect.
#[tokio::test]
async fn an_unsigned_manifest_is_refused() {
    let mut server = Server::new_async().await;
    let (_seed, public_key) = test_signing_key(9);
    let _key = PubKeyGuard::set(Some(&hex::encode(public_key)));
    let _mock = manifest_server(&mut server, MANIFEST_BODY, None).await;

    let client = ApiClient::new(server.url()).unwrap();
    let result = client.fetch_security_manifest_async().await;

    assert!(result.is_err(), "an update manifest with no signature was accepted: {result:?}");
}

/// A signature that does not match the body must not be honoured.
#[tokio::test]
async fn a_manifest_whose_body_was_tampered_with_is_refused() {
    let mut server = Server::new_async().await;
    let (seed, public_key) = test_signing_key(11);
    let _key = PubKeyGuard::set(Some(&hex::encode(public_key)));

    let honest_signature = sign(&seed, MANIFEST_BODY.as_bytes());
    let tampered = MANIFEST_BODY.replace("\"mfa_auth\":true", "\"mfa_auth\":false");
    let _mock = manifest_server(&mut server, &tampered, Some(&honest_signature)).await;

    let client = ApiClient::new(server.url()).unwrap();
    let result = client.fetch_security_manifest_async().await;

    assert!(result.is_err(), "a body edited after signing was accepted: {result:?}");
}

/// A signature from a key the client does not pin is not a signature.
#[tokio::test]
async fn a_manifest_signed_by_an_unpinned_key_is_refused() {
    let mut server = Server::new_async().await;
    let (attacker_seed, _attacker_public) = test_signing_key(13);
    let (_pinned_seed, pinned_public) = test_signing_key(17);
    let _key = PubKeyGuard::set(Some(&hex::encode(pinned_public)));

    let forged = sign(&attacker_seed, MANIFEST_BODY.as_bytes());
    let _mock = manifest_server(&mut server, MANIFEST_BODY, Some(&forged)).await;

    let client = ApiClient::new(server.url()).unwrap();
    let result = client.fetch_security_manifest_async().await;

    assert!(result.is_err(), "a manifest signed by an untrusted key was accepted: {result:?}");
}

/// With no verification key configured there is nothing to verify against, so
/// the fetch fails closed rather than silently trusting whatever arrived.
#[tokio::test]
async fn a_manifest_is_refused_when_no_verification_key_is_configured() {
    let mut server = Server::new_async().await;
    let (seed, _public) = test_signing_key(19);
    let _key = PubKeyGuard::set(None);
    let _mock =
        manifest_server(&mut server, MANIFEST_BODY, Some(&sign(&seed, MANIFEST_BODY.as_bytes())))
            .await;

    let client = ApiClient::new(server.url()).unwrap();
    let result = client.fetch_security_manifest_async().await;

    assert!(result.is_err(), "an unverifiable manifest was accepted: {result:?}");
}

/// The green half: a correctly signed manifest still reaches the caller, and the
/// flags survive intact. A fix that only ever refuses would pass the four tests
/// above.
#[tokio::test]
async fn a_correctly_signed_manifest_is_accepted_and_applied() {
    let mut server = Server::new_async().await;
    let (seed, public_key) = test_signing_key(23);
    let _key = PubKeyGuard::set(Some(&hex::encode(public_key)));
    let signature = sign(&seed, MANIFEST_BODY.as_bytes());
    let _mock = manifest_server(&mut server, MANIFEST_BODY, Some(&signature)).await;

    let client = ApiClient::new(server.url()).unwrap();
    let manifest = client
        .fetch_security_manifest_async()
        .await
        .expect("a correctly signed manifest must still be accepted");

    assert_eq!(manifest.min_client_version, "0.1.0");
    assert_eq!(manifest.flags.get("mfa_auth"), Some(&true));
    assert_eq!(manifest.flags.get("remote_panic_wipe"), Some(&true));
}
