use crate::engine::metadata::ConnectionMetadata;
use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    pub id: u64,
    pub metadata: ConnectionMetadata,
    #[serde(skip)]
    pub start_time: Instant,
    #[serde(skip)]
    pub upload_bytes: Arc<AtomicU64>,
    #[serde(skip)]
    pub download_bytes: Arc<AtomicU64>,
}

pub struct ConnectionRegistry {
    connections: RwLock<HashMap<u64, Arc<ConnectionInfo>>>,
    next_id: AtomicU64,
    total_upload: AtomicU64,
    total_download: AtomicU64,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
        }
    }

    pub fn register(&self, metadata: ConnectionMetadata) -> Arc<ConnectionInfo> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let info = Arc::new(ConnectionInfo {
            id,
            metadata,
            start_time: Instant::now(),
            upload_bytes: Arc::new(AtomicU64::new(0)),
            download_bytes: Arc::new(AtomicU64::new(0)),
        });

        let mut conns = self.connections.write();
        conns.insert(id, info.clone());
        info
    }

    pub fn remove(&self, id: u64) {
        let mut conns = self.connections.write();
        if let Some(info) = conns.remove(&id) {
            self.total_upload.fetch_add(info.upload_bytes.load(Ordering::SeqCst), Ordering::SeqCst);
            self.total_download
                .fetch_add(info.download_bytes.load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }

    pub fn list(&self) -> Vec<Arc<ConnectionInfo>> {
        let conns = self.connections.read();
        conns.values().cloned().collect()
    }

    pub fn get_stats(&self) -> (u32, u64, u64) {
        let conns = self.connections.read();
        let active = conns.len() as u32;
        let mut current_up = 0;
        let mut current_down = 0;
        for c in conns.values() {
            current_up += c.upload_bytes.load(Ordering::SeqCst);
            current_down += c.download_bytes.load(Ordering::SeqCst);
        }
        (
            active,
            self.total_upload.load(Ordering::SeqCst) + current_up,
            self.total_download.load(Ordering::SeqCst) + current_down,
        )
    }
}
