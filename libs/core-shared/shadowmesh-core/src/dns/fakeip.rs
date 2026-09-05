use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::{IpAddr, Ipv4Addr};
use tracing::info;

#[derive(Serialize, Deserialize)]
struct FakeIPState {
    ip_to_domain: HashMap<IpAddr, String>,
    domain_to_ip: HashMap<String, IpAddr>,
    lru: VecDeque<String>,
    next_ip: u32,
}

pub struct FakeIPEngine {
    ip_to_domain: Mutex<HashMap<IpAddr, String>>,
    domain_to_ip: Mutex<HashMap<String, IpAddr>>,
    lru: Mutex<VecDeque<String>>,
    max_size: usize,
    next_ip: Mutex<u32>,
    min_ip: u32,
    max_ip: u32,
}

impl FakeIPEngine {
    pub fn new(min_ip: Ipv4Addr, max_ip: Ipv4Addr, max_size: usize) -> Self {
        Self {
            ip_to_domain: Mutex::new(HashMap::new()),
            domain_to_ip: Mutex::new(HashMap::new()),
            lru: Mutex::new(VecDeque::new()),
            max_size,
            next_ip: Mutex::new(u32::from(min_ip)),
            min_ip: u32::from(min_ip),
            max_ip: u32::from(max_ip),
        }
    }

    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let state = FakeIPState {
            ip_to_domain: self.ip_to_domain.lock().clone(),
            domain_to_ip: self.domain_to_ip.lock().clone(),
            lru: self.lru.lock().clone(),
            next_ip: *self.next_ip.lock(),
        };

        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &state)?;
        info!("FakeIP state saved to {}", path);
        Ok(())
    }

    pub fn load(&self, path: &str) -> anyhow::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let state: FakeIPState = serde_json::from_reader(reader)?;

        *self.ip_to_domain.lock() = state.ip_to_domain;
        *self.domain_to_ip.lock() = state.domain_to_ip;
        *self.lru.lock() = state.lru;
        *self.next_ip.lock() = state.next_ip;

        info!("FakeIP state loaded from {}", path);
        Ok(())
    }

    pub fn get_ip(&self, domain: &str) -> IpAddr {
        let mut domain_to_ip = self.domain_to_ip.lock();
        if let Some(ip) = domain_to_ip.get(domain) {
            // Update LRU
            let mut lru = self.lru.lock();
            if let Some(pos) = lru.iter().position(|d| d == domain) {
                lru.remove(pos);
            }
            lru.push_back(domain.to_string());
            return *ip;
        }

        // Allocate new IP
        let mut next_ip_guard = self.next_ip.lock();
        let ip_val = *next_ip_guard;
        if *next_ip_guard >= self.max_ip {
            *next_ip_guard = self.min_ip;
        } else {
            *next_ip_guard += 1;
        }
        drop(next_ip_guard);

        let ip = IpAddr::V4(Ipv4Addr::from(ip_val));

        // Handle eviction
        let mut ip_to_domain = self.ip_to_domain.lock();
        let mut lru = self.lru.lock();

        if lru.len() >= self.max_size {
            if let Some(old_domain) = lru.pop_front() {
                if let Some(old_ip) = domain_to_ip.remove(&old_domain) {
                    ip_to_domain.remove(&old_ip);
                }
            }
        }

        domain_to_ip.insert(domain.to_string(), ip);
        ip_to_domain.insert(ip, domain.to_string());
        lru.push_back(domain.to_string());

        ip
    }

    pub fn get_domain(&self, ip: IpAddr) -> Option<String> {
        let ip_to_domain = self.ip_to_domain.lock();
        ip_to_domain.get(&ip).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_engine() {
        let engine =
            FakeIPEngine::new(Ipv4Addr::new(198, 18, 0, 1), Ipv4Addr::new(198, 18, 0, 10), 5);

        let ip1 = engine.get_ip("example.com");
        assert_eq!(ip1, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)));
        assert_eq!(engine.get_domain(ip1), Some("example.com".to_string()));

        let ip2 = engine.get_ip("google.com");
        assert_eq!(ip2, IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)));

        // Test LRU and eviction
        engine.get_ip("a.com");
        engine.get_ip("b.com");
        engine.get_ip("c.com"); // Now we have 5 entries

        let ip_d = engine.get_ip("d.com"); // Should evict "example.com"
        assert_eq!(engine.get_domain(ip1), None);
        assert_eq!(engine.get_domain(ip_d), Some("d.com".to_string()));
    }
}
