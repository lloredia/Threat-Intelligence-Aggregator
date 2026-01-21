//! DNS enrichment provider

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use crate::enrichment::EnrichmentProvider;
use crate::models::{DnsData, Indicator, IocType};

/// DNS enrichment provider
pub struct DnsProvider {
    resolver: TokioAsyncResolver,
}

impl DnsProvider {
    /// Create a new DNS provider
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Ok(Self { resolver })
    }

    /// Perform DNS lookups for a domain
    pub async fn lookup(&self, domain: &str) -> Result<DnsData> {
        let mut data = DnsData::default();

        // A records
        if let Ok(response) = self.resolver.lookup_ip(domain).await {
            for ip in response.iter() {
                match ip {
                    std::net::IpAddr::V4(v4) => data.a_records.push(v4.to_string()),
                    std::net::IpAddr::V6(v6) => data.aaaa_records.push(v6.to_string()),
                }
            }
        }

        // MX records
        if let Ok(response) = self.resolver.mx_lookup(domain).await {
            for record in response.iter() {
                data.mx_records.push(record.exchange().to_string());
            }
        }

        // TXT records
        if let Ok(response) = self.resolver.txt_lookup(domain).await {
            for record in response.iter() {
                let txt: String = record.iter()
                    .map(|d| String::from_utf8_lossy(d).to_string())
                    .collect();
                data.txt_records.push(txt);
            }
        }

        // NS records
        if let Ok(response) = self.resolver.ns_lookup(domain).await {
            for record in response.iter() {
                data.ns_records.push(record.to_string());
            }
        }

        Ok(data)
    }

    /// Reverse DNS lookup for an IP
    pub async fn reverse_lookup(&self, ip: &str) -> Result<Vec<String>> {
        let ip_addr: std::net::IpAddr = ip.parse()?;
        let mut results = vec![];

        if let Ok(response) = self.resolver.reverse_lookup(ip_addr).await {
            for name in response.iter() {
                results.push(name.to_string());
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl EnrichmentProvider for DnsProvider {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn enrichment_type(&self) -> &'static str {
        "dns"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Domain | IocType::Ip)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        match indicator.ioc_type {
            IocType::Domain => {
                let data = self.lookup(&indicator.value).await?;
                
                // Only return if we got some data
                if data.a_records.is_empty() 
                    && data.mx_records.is_empty() 
                    && data.ns_records.is_empty() 
                {
                    return Ok(None);
                }

                Ok(Some(json!({
                    "a_records": data.a_records,
                    "aaaa_records": data.aaaa_records,
                    "mx_records": data.mx_records,
                    "txt_records": data.txt_records,
                    "ns_records": data.ns_records,
                    "cname_records": data.cname_records,
                })))
            }
            IocType::Ip => {
                let ptr_records = self.reverse_lookup(&indicator.value).await?;
                
                if ptr_records.is_empty() {
                    return Ok(None);
                }

                Ok(Some(json!({
                    "ptr_records": ptr_records,
                })))
            }
            _ => Ok(None),
        }
    }

    fn ttl_hours(&self) -> i64 {
        24 // DNS can change frequently
    }
}
