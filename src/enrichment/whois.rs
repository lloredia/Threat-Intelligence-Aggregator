//! WHOIS enrichment provider

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::enrichment::EnrichmentProvider;
use crate::models::{Indicator, IocType, WhoisData};

/// WHOIS enrichment provider
pub struct WhoisProvider {
    // Could add configuration here for custom WHOIS servers
}

impl WhoisProvider {
    /// Create a new WHOIS provider
    pub fn new() -> Self {
        Self {}
    }

    /// Perform WHOIS lookup for a domain
    pub async fn lookup(&self, domain: &str) -> Result<WhoisData> {
        // Use whois-rust crate for synchronous lookup
        // Wrap in spawn_blocking for async compatibility
        let domain = domain.to_string();
        
        let result = tokio::task::spawn_blocking(move || {
            whois_rust::WhoIs::from_path("./data/servers.json")
                .or_else(|_| whois_rust::WhoIs::from_string(include_str!("../../data/whois_servers.json")))
                .ok()
                .and_then(|whois| whois.lookup(whois_rust::WhoIsLookupOptions::from_string(&domain).ok()?).ok())
        })
        .await
        .context("WHOIS lookup task failed")?;

        let raw = result.unwrap_or_default();
        let data = parse_whois_response(&raw);
        
        Ok(data)
    }
}

impl Default for WhoisProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse raw WHOIS response into structured data
fn parse_whois_response(raw: &str) -> WhoisData {
    let mut data = WhoisData {
        raw: Some(raw.to_string()),
        ..Default::default()
    };

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            if value.is_empty() {
                continue;
            }

            match key.as_str() {
                "registrar" | "registrar name" => {
                    if data.registrar.is_none() {
                        data.registrar = Some(value.to_string());
                    }
                }
                "registrant" | "registrant name" => {
                    data.registrant = Some(value.to_string());
                }
                "registrant organization" | "registrant org" => {
                    data.registrant_org = Some(value.to_string());
                }
                "registrant country" => {
                    data.registrant_country = Some(value.to_string());
                }
                "creation date" | "created" | "created date" | "registration date" => {
                    // Parse date - simplified, just store as string for now
                    // In production, use chrono to parse various date formats
                }
                "expiration date" | "expires" | "expiry date" | "registry expiry date" => {
                    // Parse date
                }
                "name server" | "nserver" => {
                    data.name_servers.push(value.to_lowercase());
                }
                "status" | "domain status" => {
                    data.status.push(value.to_string());
                }
                _ => {}
            }
        }
    }

    data
}

#[async_trait]
impl EnrichmentProvider for WhoisProvider {
    fn name(&self) -> &'static str {
        "whois"
    }

    fn enrichment_type(&self) -> &'static str {
        "whois"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Domain)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        let data = self.lookup(&indicator.value).await?;

        // Only return if we got some meaningful data
        if data.registrar.is_none() && data.name_servers.is_empty() {
            return Ok(None);
        }

        Ok(Some(json!({
            "registrar": data.registrar,
            "registrant": data.registrant,
            "registrant_org": data.registrant_org,
            "registrant_country": data.registrant_country,
            "name_servers": data.name_servers,
            "status": data.status,
        })))
    }

    fn ttl_hours(&self) -> i64 {
        168 // 1 week - WHOIS data changes infrequently
    }
}
