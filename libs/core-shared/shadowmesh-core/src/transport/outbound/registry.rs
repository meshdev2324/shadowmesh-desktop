use crate::transport::traits::OutboundDialer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct OutboundRegistry {
    outbounds: RwLock<HashMap<String, Arc<dyn OutboundDialer>>>,
}

impl Default for OutboundRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self { outbounds: RwLock::new(HashMap::new()) }
    }

    pub async fn register(&self, outbound: Arc<dyn OutboundDialer>) {
        let mut map = self.outbounds.write().await;
        map.insert(outbound.tag().to_string(), outbound);
    }

    pub async fn get(&self, tag: &str) -> Option<Arc<dyn OutboundDialer>> {
        let map = self.outbounds.read().await;
        map.get(tag).cloned()
    }
}
