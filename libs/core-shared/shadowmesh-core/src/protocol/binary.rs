use crate::ShadowMeshError;
use crate::VPNNode;
use serde::{Deserialize, Serialize};

/// A borrowed version of `VPNNode` for zero-copy deserialization.
///
/// This struct uses `&'a str` to point directly into the input buffer,
/// eliminating allocations during deserialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VPNNodeBorrowed<'a> {
    /// Unique identifier for the node.
    pub id: &'a str,
    /// Display name of the node.
    pub name: &'a str,
    /// Region where the node is located.
    pub region: &'a str,
    /// ISO country code.
    pub country: &'a str,
    /// Network endpoint (IP:Port).
    pub endpoint: &'a str,
    /// Node's WireGuard public key.
    pub public_key: &'a str,
    /// Current server load (0-100).
    pub load: u32,
    /// Measured latency in milliseconds.
    pub latency: u32,
    /// Whether the node is sovereign.
    pub is_sovereign: bool,
    /// Whether the node is currently reachable.
    pub is_online: bool,
}

impl<'a> From<&'a VPNNode> for VPNNodeBorrowed<'a> {
    fn from(node: &'a VPNNode) -> Self {
        Self {
            id: &node.id,
            name: &node.name,
            region: &node.region,
            country: &node.country,
            endpoint: &node.endpoint,
            public_key: &node.public_key,
            load: node.load,
            latency: node.latency,
            is_sovereign: node.is_sovereign,
            is_online: node.is_online,
        }
    }
}

impl<'a> VPNNodeBorrowed<'a> {
    /// Converts the borrowed node into an owned `VPNNode`.
    pub fn to_owned(&self) -> VPNNode {
        VPNNode {
            id: self.id.to_string(),
            name: self.name.to_string(),
            region: self.region.to_string(),
            country: self.country.to_string(),
            endpoint: self.endpoint.to_string(),
            public_key: self.public_key.to_string(),
            load: self.load,
            latency: self.latency,
            is_sovereign: self.is_sovereign,
            is_online: self.is_online,
            shard_id: None,
        }
    }
}

/// Magic bytes to identify the ShadowMesh Binary format.
pub const MAGIC: &[u8; 4] = b"SMB\x01";

/// Encodes a list of nodes into the zero-copy binary format.
pub fn encode_node_list(nodes: &[VPNNodeBorrowed<'_>]) -> Result<Vec<u8>, ShadowMeshError> {
    let mut buf = Vec::with_capacity(nodes.len() * 128 + 4);
    buf.extend_from_slice(MAGIC);
    postcard::to_io(nodes, &mut buf)
        .map_err(|e| ShadowMeshError::Other(format!("Serialization failed: {}", e)))?;
    Ok(buf)
}

/// Decodes a list of nodes from the zero-copy binary format.
///
/// This function is zero-copy and returns references into the `data` buffer.
pub fn decode_node_list<'a>(data: &'a [u8]) -> Result<Vec<VPNNodeBorrowed<'a>>, ShadowMeshError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        return Err(ShadowMeshError::Other("Invalid magic bytes for binary format".to_string()));
    }

    postcard::from_bytes(&data[4..])
        .map_err(|e| ShadowMeshError::Other(format!("Deserialization failed: {}", e)))
}

/// Decodes any owned type from the binary format.
pub fn decode_node_list_generic<T: serde::de::DeserializeOwned>(
    data: &[u8],
) -> Result<T, ShadowMeshError> {
    if data.len() < 4 || &data[..4] != MAGIC {
        return Err(ShadowMeshError::Other("Invalid magic bytes for binary format".to_string()));
    }

    postcard::from_bytes(&data[4..])
        .map_err(|e| ShadowMeshError::Other(format!("Deserialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_binary_roundtrip(
            id in "[a-zA-Z0-9]{8}",
            name in "[a-zA-Z0-9 ]{1,32}",
            region in "[a-z]{2}",
            country in "[A-Z]{2}",
            endpoint in "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{2,5}",
            public_key in "[a-zA-Z0-9+/]{43}=",
            load in 0u32..100u32,
            latency in 0u32..1000u32,
            is_sovereign in any::<bool>(),
            is_online in any::<bool>()
        ) {
            let node = VPNNodeBorrowed {
                id: &id,
                name: &name,
                region: &region,
                country: &country,
                endpoint: &endpoint,
                public_key: &public_key,
                load,
                latency,
                is_sovereign,
                is_online,
            };

            let nodes = vec![node.clone()];
            let encoded = encode_node_list(&nodes).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let decoded = decode_node_list(&encoded).map_err(|e| TestCaseError::fail(e.to_string()))?;

            prop_assert_eq!(nodes, decoded);
        }
    }
}
