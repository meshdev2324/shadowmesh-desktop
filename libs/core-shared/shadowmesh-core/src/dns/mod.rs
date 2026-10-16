pub mod fakeip;
pub mod upstream;

use crate::engine::metadata::DnsQueryType;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
pub use fakeip::FakeIPEngine;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Interface for DNS upstreams (UDP, DoH, etc).
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, domain: &str, query_type: DnsQueryType) -> Result<Vec<IpAddr>>;
}

/// Cache entry: resolved addresses with their insertion instant.
type DnsCacheEntry = (Vec<IpAddr>, Instant);

/// A simple DNS cache with TTL support.
pub struct DnsCache {
    entries: RwLock<HashMap<(String, DnsQueryType), DnsCacheEntry>>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self { entries: RwLock::new(HashMap::new()), ttl: Duration::from_secs(ttl_secs) }
    }

    pub fn get(&self, domain: &str, query_type: DnsQueryType) -> Option<Vec<IpAddr>> {
        let entries = self.entries.read();
        if let Some((ips, expiry)) = entries.get(&(domain.to_string(), query_type)) {
            if Instant::now() < *expiry {
                return Some(ips.clone());
            }
        }
        None
    }

    pub fn put(&self, domain: &str, query_type: DnsQueryType, ips: Vec<IpAddr>) {
        let mut entries = self.entries.write();
        entries.insert((domain.to_string(), query_type), (ips, Instant::now() + self.ttl));
    }

    pub fn purge(&self) {
        let mut entries = self.entries.write();
        let now = Instant::now();
        entries.retain(|_, (_, expiry)| *expiry > now);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionModel {
    Serial,
    Race,
}

/// Orchestrates DNS resolution across multiple upstreams with caching and Fake-IP support.
pub struct DnsRouter {
    upstreams: Vec<Arc<dyn DnsResolver>>,
    fake_ip: Option<FakeIPEngine>,
    cache: Arc<DnsCache>,
    execution_model: ExecutionModel,
}

impl DnsRouter {
    pub fn new(upstreams: Vec<Arc<dyn DnsResolver>>, execution_model: ExecutionModel) -> Self {
        Self {
            upstreams,
            fake_ip: None,
            cache: Arc::new(DnsCache::new(300)), // 5 minute default TTL
            execution_model,
        }
    }

    pub fn set_fake_ip(&mut self, engine: FakeIPEngine) {
        self.fake_ip = Some(engine);
    }

    pub fn fake_ip(&self) -> Option<&FakeIPEngine> {
        self.fake_ip.as_ref()
    }

    pub async fn resolve(&self, domain: &str, query_type: DnsQueryType) -> Result<Vec<IpAddr>> {
        // 1. Fake-IP check (only for A/AAAA)
        if matches!(query_type, DnsQueryType::A | DnsQueryType::AAAA) {
            if let Some(fake_ip) = &self.fake_ip {
                return Ok(vec![fake_ip.get_ip(domain)]);
            }
        }

        // 2. Cache check
        if let Some(ips) = self.cache.get(domain, query_type.clone()) {
            return Ok(ips);
        }

        // 3. Upstream resolution
        let result = match self.execution_model {
            ExecutionModel::Serial => {
                let mut last_err = anyhow!("No upstreams configured");
                for upstream in &self.upstreams {
                    match upstream.resolve(domain, query_type.clone()).await {
                        Ok(ips) => {
                            self.cache.put(domain, query_type, ips.clone());
                            return Ok(ips);
                        }
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
            ExecutionModel::Race => {
                let mut set = tokio::task::JoinSet::new();
                for upstream in &self.upstreams {
                    let domain = domain.to_string();
                    let qt = query_type.clone();
                    let upstream = upstream.clone();
                    set.spawn(async move { upstream.resolve(&domain, qt).await });
                }

                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(ips)) => {
                            self.cache.put(domain, query_type, ips.clone());
                            return Ok(ips);
                        }
                        _ => continue,
                    }
                }
                Err(anyhow!("All upstreams failed for {}", domain))
            }
        };

        result
    }

    pub async fn lookup_reverse(&self, ip: IpAddr) -> Option<String> {
        if let Some(fake_ip) = &self.fake_ip {
            if let Some(domain) = fake_ip.get_domain(ip) {
                return Some(domain);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    struct SlowResolver(Duration, Vec<IpAddr>);
    #[async_trait]
    impl DnsResolver for SlowResolver {
        async fn resolve(&self, _domain: &str, _query_type: DnsQueryType) -> Result<Vec<IpAddr>> {
            sleep(self.0).await;
            Ok(self.1.clone())
        }
    }

    #[tokio::test]
    async fn test_race_dns() {
        let r1 =
            Arc::new(SlowResolver(Duration::from_millis(100), vec!["1.1.1.1".parse().unwrap()]));
        let r2 =
            Arc::new(SlowResolver(Duration::from_millis(10), vec!["8.8.8.8".parse().unwrap()]));

        let router = DnsRouter::new(vec![r1, r2], ExecutionModel::Race);
        let ips = router.resolve("google.com", DnsQueryType::A).await.unwrap();

        assert_eq!(ips[0], "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_dns_cache() {
        let resolver =
            Arc::new(SlowResolver(Duration::from_millis(0), vec!["1.2.3.4".parse().unwrap()]));
        let router = DnsRouter::new(vec![resolver], ExecutionModel::Serial);

        // First resolve - should hit upstream
        let ips = router.resolve("test.com", DnsQueryType::A).await.unwrap();
        assert_eq!(ips[0], "1.2.3.4".parse::<IpAddr>().unwrap());

        // Cache should be populated
        assert!(router.cache.get("test.com", DnsQueryType::A).is_some());
    }
}
