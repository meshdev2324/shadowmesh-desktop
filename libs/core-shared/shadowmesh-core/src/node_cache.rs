use crate::ShadowMeshError;
use crate::VPNNode;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
struct CacheEntry {
    node: VPNNode,
    lru_counter: u64,
    ttl_seconds: u64,
    created_at: u64,
}

/// An in-memory cache for VPN nodes with LRU eviction and TTL support.
///
/// SOP 01: Optimized with sharded DashMap and Atomic metrics to minimize lookup latency.
pub struct NodeCache {
    cache: DashMap<String, CacheEntry>,
    max_size: usize,
    default_ttl_seconds: u64,
    lru_global_counter: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl NodeCache {
    /// Creates a new `NodeCache` with the specified maximum size and default TTL.
    pub fn new(max_size: usize, default_ttl_seconds: u64) -> Self {
        NodeCache {
            cache: DashMap::new(),
            max_size,
            default_ttl_seconds,
            lru_global_counter: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    fn get_current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn next_lru_counter(&self) -> u64 {
        self.lru_global_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Retrieves a node from the cache by its ID.
    ///
    /// Returns `None` if the node is not in the cache or if it has expired.
    pub fn get(&self, node_id: String) -> Option<VPNNode> {
        let now = Self::get_current_time();
        let counter = self.next_lru_counter();

        if let Some(mut entry) = self.cache.get_mut(&node_id) {
            if now < entry.created_at + entry.ttl_seconds {
                entry.lru_counter = counter;
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.node.clone());
            } else {
                drop(entry);
                self.cache.remove(&node_id);
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Puts a node into the cache with the default TTL.
    pub fn put(&self, node: VPNNode) {
        self.put_with_ttl(node, self.default_ttl_seconds)
    }

    fn put_with_ttl(&self, node: VPNNode, ttl_seconds: u64) {
        let now = Self::get_current_time();
        let counter = self.next_lru_counter();

        if self.cache.len() >= self.max_size && !self.cache.contains_key(&node.id) {
            let lru_key =
                self.cache.iter().min_by_key(|r| r.value().lru_counter).map(|r| r.key().clone());

            if let Some(key) = lru_key {
                self.cache.remove(&key);
            }
        }

        self.cache.insert(
            node.id.clone(),
            CacheEntry { node, lru_counter: counter, ttl_seconds, created_at: now },
        );
    }

    /// Puts multiple nodes into the cache.
    pub fn put_all(&self, nodes: Vec<VPNNode>) {
        for node in nodes {
            self.cache.insert(
                node.id.clone(),
                CacheEntry {
                    node,
                    lru_counter: self.next_lru_counter(),
                    ttl_seconds: self.default_ttl_seconds,
                    created_at: Self::get_current_time(),
                },
            );
        }
    }

    /// Retrieves all nodes currently stored in the cache.
    pub fn get_all(&self) -> Vec<VPNNode> {
        self.cache.iter().map(|r| r.value().node.clone()).collect()
    }

    /// Calculates the cache hit rate (0.0 to 1.0).
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Persists the cached nodes to a JSON file on disk.
    pub fn save_to_disk(&self, path: String) -> Result<(), ShadowMeshError> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let nodes = self.get_all();
        let json = serde_json::to_string(&nodes)?;

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(json.as_bytes())?;
        temp_file.flush()?;
        temp_file.persist(path).map_err(|e| ShadowMeshError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Clears all nodes and statistics from the cache.
    pub fn clear(&self) {
        self.cache.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VPNNode;

    #[test]
    fn test_put_and_get() -> Result<(), ShadowMeshError> {
        let cache = NodeCache::new(10, 3600);
        let node = VPNNode {
            id: "test-node".to_string(),
            name: "Test Node".to_string(),
            region: "test-region".to_string(),
            country: "Test Country".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            public_key: "test-key".to_string(),
            load: 50,
            latency: 100,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };

        cache.put(node.clone());
        let retrieved = cache.get("test-node".to_string());
        assert!(retrieved.is_some());
        assert_eq!(retrieved.ok_or(ShadowMeshError::NodeNotFound)?.id, node.id);
        Ok(())
    }

    #[test]
    fn test_get_missing() {
        let cache = NodeCache::new(10, 3600);
        let retrieved = cache.get("missing-node".to_string());
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_eviction() {
        let cache = NodeCache::new(2, 3600);

        let node1 = VPNNode {
            id: "n1".to_string(),
            name: "Node1".to_string(),
            region: "r".to_string(),
            country: "c".to_string(),
            endpoint: "e1".to_string(),
            public_key: "k1".to_string(),
            load: 1,
            latency: 1,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        let node2 = VPNNode {
            id: "n2".to_string(),
            name: "Node2".to_string(),
            region: "r".to_string(),
            country: "c".to_string(),
            endpoint: "e2".to_string(),
            public_key: "k2".to_string(),
            load: 2,
            latency: 2,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        let node3 = VPNNode {
            id: "n3".to_string(),
            name: "Node3".to_string(),
            region: "r".to_string(),
            country: "c".to_string(),
            endpoint: "e3".to_string(),
            public_key: "k3".to_string(),
            load: 3,
            latency: 3,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };

        cache.put(node1);
        cache.put(node2);
        cache.put(node3); // should evict n1

        assert!(cache.get("n1".to_string()).is_none());
        assert!(cache.get("n2".to_string()).is_some());
        assert!(cache.get("n3".to_string()).is_some());
    }

    #[test]
    fn test_hit_rate() {
        let cache = NodeCache::new(10, 3600);

        let node = VPNNode {
            id: "test".to_string(),
            name: "Test".to_string(),
            region: "r".to_string(),
            country: "c".to_string(),
            endpoint: "e".to_string(),
            public_key: "k".to_string(),
            load: 0,
            latency: 0,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        cache.put(node);

        cache.get("test".to_string());
        cache.get("test".to_string());
        cache.get("test".to_string());
        cache.get("missing".to_string());

        let hit_rate = cache.hit_rate();
        assert_eq!(hit_rate, 0.75);
    }

    #[test]
    fn test_save_to_disk() -> Result<(), ShadowMeshError> {
        use tempfile::NamedTempFile;
        let cache = NodeCache::new(10, 3600);

        let node = VPNNode {
            id: "test-node".to_string(),
            name: "Test Node".to_string(),
            region: "test-region".to_string(),
            country: "Test Country".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            public_key: "test-key".to_string(),
            load: 50,
            latency: 100,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        cache.put(node);

        let temp_file =
            NamedTempFile::new().map_err(|e| ShadowMeshError::IoError(e.to_string()))?;
        let path = temp_file
            .path()
            .to_str()
            .ok_or_else(|| ShadowMeshError::Other("Invalid path".into()))?
            .to_string();
        cache.save_to_disk(path)?;
        Ok(())
    }

    #[test]
    fn test_clear() {
        let cache = NodeCache::new(10, 3600);
        let node = VPNNode {
            id: "test-node".to_string(),
            name: "Test Node".to_string(),
            region: "test-region".to_string(),
            country: "Test Country".to_string(),
            endpoint: "1.2.3.4:51820".to_string(),
            public_key: "test-key".to_string(),
            load: 50,
            latency: 100,
            is_sovereign: false,
            is_online: true,
            shard_id: None,
        };
        cache.put(node);
        cache.clear();

        assert!(cache.get("test-node".to_string()).is_none());
        assert_eq!(cache.hit_rate(), 0.0);
    }
}
