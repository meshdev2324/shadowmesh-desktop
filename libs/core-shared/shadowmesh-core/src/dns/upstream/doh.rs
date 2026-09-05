use crate::dns::DnsResolver;
use crate::engine::metadata::DnsQueryType;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;
use tracing::debug;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

pub struct DoHDnsUpstream {
    url: String,
    client: Client,
}

impl DoHDnsUpstream {
    pub fn new(url: String) -> Self {
        Self { url, client: Client::new() }
    }
}

#[async_trait]
impl DnsResolver for DoHDnsUpstream {
    async fn resolve(&self, domain: &str, query_type: DnsQueryType) -> Result<Vec<IpAddr>> {
        let type_str = match query_type {
            DnsQueryType::A => "A",
            DnsQueryType::AAAA => "AAAA",
            DnsQueryType::Cname => "CNAME",
            DnsQueryType::Mx => "MX",
            DnsQueryType::Txt => "TXT",
            DnsQueryType::Ptr => "PTR",
            DnsQueryType::Srv => "SRV",
            DnsQueryType::Https => "HTTPS",
            DnsQueryType::Svcb => "SVCB",
            DnsQueryType::Unknown(v) => &v.to_string(),
        };

        let url = format!("{}?name={}&type={}", self.url, domain, type_str);
        debug!("Querying DoH: {}", url);

        let response = self.client.get(url).header("accept", "application/dns-json").send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("DoH query failed with status {}", response.status()));
        }

        let doh_res: DohResponse = response.json().await?;

        let mut ips = Vec::new();
        if let Some(answers) = doh_res.answer {
            for answer in answers {
                if let Ok(ip) = answer.data.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
        }

        if ips.is_empty() {
            return Err(anyhow!("No records found for {} ({})", domain, type_str));
        }

        Ok(ips)
    }
}
