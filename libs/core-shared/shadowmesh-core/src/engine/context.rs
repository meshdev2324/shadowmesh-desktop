use crate::engine::metadata::ConnectionMetadata;
use parking_lot::Mutex;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub metadata: ConnectionMetadata,
    pub detour_path: Vec<String>,
    pub rule_match_history: Vec<String>,
}

impl ConnectionContext {
    pub fn new(metadata: ConnectionMetadata) -> Self {
        Self { metadata, detour_path: Vec::new(), rule_match_history: Vec::new() }
    }
}

pub type SharedContext = Arc<Mutex<ConnectionContext>>;
