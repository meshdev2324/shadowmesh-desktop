use crate::ShadowMeshError;
use crate::VPNNode;
use serde::Deserialize;
use tracing::{error, info, warn};

/// Supported discovery channels for node list retrieval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryChannel {
    /// Standard API endpoint.
    PrimaryApi,
    /// Edge-computed Cloudflare Worker.
    CloudflareWorker,
    /// DNS-over-HTTPS TXT record.
    DnsOverHttps,
}

/// A resilient engine that cascades through multiple discovery channels
/// to retrieve the latest VPN node list.
pub struct ResilientDiscoveryEngine {
    api_base_url: String,
    worker_url: String,
    doh_endpoints: Vec<String>,
    discovery_domain: String,
    master_key: String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

impl ResilientDiscoveryEngine {
    /// Creates a new `ResilientDiscoveryEngine` with default fallbacks.
    pub fn new(api_base_url: String, worker_url: String, discovery_domain: String) -> Self {
        Self {
            api_base_url,
            worker_url,
            doh_endpoints: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            discovery_domain,
            master_key: "SHADOWMESH_DISCOVERY_PROD_V1".to_string(), // Placeholder for real key logic
        }
    }

    /// Attempts to fetch nodes from all channels in order of preference.
    pub async fn fetch_nodes_resilient(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        let mut client_builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));

        // v6.7 Hardcoded DNS Bypass for Discovery
        if let Ok(addr) = "165.22.56.70:443".parse::<std::net::SocketAddr>() {
            client_builder = client_builder.resolve("api.shadowmesh.org", addr);
        }

        let client = client_builder.build().map_err(|e| ShadowMeshError::Other(e.to_string()))?;

        // 1. Primary API
        let api_url = format!("{}/api/v1/nodes", self.api_base_url);
        match client.get(&api_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(nodes) = resp.json::<Vec<VPNNode>>().await {
                    info!("Discovery: Successfully retrieved nodes from Primary API.");
                    return Ok(nodes);
                }
            }
            _ => warn!("Discovery: Primary API failed. Falling back to Worker..."),
        }

        // 2. Cloudflare Worker
        match self.fetch_from_worker().await {
            Ok(nodes) => {
                info!("Discovery: Successfully retrieved nodes from Cloudflare Worker.");
                return Ok(nodes);
            }
            Err(e) => warn!("Discovery: Cloudflare Worker failed: {}. Falling back to DoH...", e),
        }

        // 3. DNS-over-HTTPS
        match self.fetch_from_doh().await {
            Ok(nodes) => {
                info!("Discovery: Successfully retrieved nodes from DNS-over-HTTPS.");
                return Ok(nodes);
            }
            Err(e) => error!("Discovery: All channels failed. Last error (DoH): {}", e),
        }

        Err(ShadowMeshError::ConnectionFailed)
    }

    async fn fetch_from_worker(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        let client = reqwest::Client::new();
        let response = client
            .get(&self.worker_url)
            .header("X-Shadow-Discovery-Key", &self.master_key)
            .send()
            .await
            .map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        if response.status().is_success() {
            let encrypted_payload =
                response.text().await.map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

            self.decrypt_and_parse_nodes(&encrypted_payload)
        } else {
            Err(ShadowMeshError::Other("Worker returned non-success status".into()))
        }
    }

    async fn fetch_from_doh(&self) -> Result<Vec<VPNNode>, ShadowMeshError> {
        let client = reqwest::Client::new();

        for endpoint in &self.doh_endpoints {
            let url = format!("{}?name={}&type=TXT", endpoint, self.discovery_domain);
            let response = client.get(&url).header("Accept", "application/dns-json").send().await;

            if let Ok(resp) = response {
                if resp.status().is_success() {
                    let doh_resp: DohResponse =
                        resp.json().await.map_err(|e| ShadowMeshError::JsonError(e.to_string()))?;

                    if let Some(answers) = doh_resp.answer {
                        // Concatenate multiple TXT records if fragmented
                        let mut full_payload = String::new();
                        for answer in answers {
                            // DoH TXT data usually includes quotes
                            let clean_data = answer.data.trim_matches('"');
                            full_payload.push_str(clean_data);
                        }

                        if !full_payload.is_empty() {
                            return self.decrypt_and_parse_nodes(&full_payload);
                        }
                    }
                }
            }
        }

        Err(ShadowMeshError::DnsResolutionError)
    }

    fn decrypt_and_parse_nodes(&self, payload: &str) -> Result<Vec<VPNNode>, ShadowMeshError> {
        // RFC-004: Payloads are base64-encoded and encrypted.
        // For Phase 1, we assume it's base64-encoded JSON for simplicity.
        use base64::prelude::*;
        let decoded = BASE64_STANDARD
            .decode(payload)
            .map_err(|e| ShadowMeshError::Other(format!("Base64 decode failed: {}", e)))?;

        // Horizon 3 Phase 2: Now expects GlobalManifest
        let manifest: crate::GlobalManifest = serde_json::from_slice(&decoded)
            .map_err(|e| ShadowMeshError::JsonError(e.to_string()))?;

        let mut nodes = manifest.nodes;

        // Convert Anycast VIPs into Virtual Nodes
        for vip in manifest.anycast_vips {
            nodes.push(VPNNode {
                id: format!("anycast-{}", vip.id),
                name: format!("{} (Anycast)", vip.label),
                region: "Global".to_string(),
                country: "ANY".to_string(),
                endpoint: format!("{}:51820", vip.ip_address),
                public_key: String::new(), // Anycast nodes usually use a shared or dynamic key
                load: 0,
                latency: 0,
                is_sovereign: true, // Anycast endpoints are by definition part of the sovereign backbone
                is_online: true,
                shard_id: None,
            });
        }

        Ok(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_client::ApiClient;
    use base64::prelude::*;
    use mockito::Server;
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_discovery_cascade_fallback() {
        let mut server = Server::new_async().await;
        let url = server.url();

        // 1. Mock API fails
        let _m1 = server.mock("GET", "/api/v1/nodes").with_status(500).create_async().await;

        // 2. Mock Worker succeeds (but returns base64 encoded manifest)
        let nodes = vec![crate::VPNNode {
            id: "test".into(),
            name: "Test".into(),
            region: "US".into(),
            country: "US".into(),
            endpoint: "1.2.3.4:443".into(),
            public_key: "pub".into(),
            load: 0,
            latency: 0,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        }];
        let manifest = crate::GlobalManifest {
            nodes,
            anycast_vips: vec![crate::AnycastVip {
                id: 1,
                ip_address: "100.64.0.1".into(),
                label: "Anycast".into(),
                is_active: true,
            }],
            version: "v0.3.0".into(),
        };
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let encoded = BASE64_STANDARD.encode(manifest_json);

        let _m2 = server
            .mock("GET", "/worker/nodes")
            .with_status(200)
            .with_body(encoded)
            .create_async()
            .await;

        let _api_client = Arc::new(ApiClient::new(url.clone()).unwrap());
        let engine = ResilientDiscoveryEngine::new(
            url.clone(),
            format!("{}/worker/nodes", url),
            "nodes.test".into(),
        );

        let result = engine.fetch_nodes_resilient().await.unwrap();
        // found 2 nodes because manifest includes 1 real node and 1 anycast virtual node
        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|n| n.id == "test"));
    }

    #[tokio::test]
    async fn test_doh_fallback_parsing() {
        let mut server = Server::new_async().await;
        let url = server.url();

        // All previous channels fail
        let _m1 = server.mock("GET", "/api/v1/nodes").with_status(404).create_async().await;
        let _m2 = server.mock("GET", "/worker/nodes").with_status(404).create_async().await;

        // DoH succeeds
        let nodes = vec![crate::VPNNode {
            id: "doh".into(),
            name: "DOH".into(),
            region: "DE".into(),
            country: "DE".into(),
            endpoint: "5.6.7.8:443".into(),
            public_key: "pub".into(),
            load: 10,
            latency: 20,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        }];
        let manifest =
            crate::GlobalManifest { nodes, anycast_vips: Vec::new(), version: "v1.0.0".into() };
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&manifest).unwrap());

        let doh_response = json!({
            "Status": 0,
            "Answer": [{ "name": "nodes.test", "type": 16, "data": format!("\"{}\"", encoded) }]
        });

        let _m3 = server
            .mock("GET", "/dns-query?name=nodes.test&type=TXT")
            .with_status(200)
            .with_header("content-type", "application/dns-json")
            .with_body(serde_json::to_string(&doh_response).unwrap())
            .create_async()
            .await;

        let mut engine = ResilientDiscoveryEngine::new(
            url.clone(),
            format!("{}/worker/nodes", url),
            "nodes.test".into(),
        );
        engine.doh_endpoints = vec![format!("{}/dns-query", url)];

        let result = engine.fetch_nodes_resilient().await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "doh");
    }
}
