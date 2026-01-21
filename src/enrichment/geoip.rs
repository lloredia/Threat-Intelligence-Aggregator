//! GeoIP enrichment using MaxMind database

use anyhow::{Context, Result};
use async_trait::async_trait;
use maxminddb::{geoip2, Reader};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::enrichment::EnrichmentProvider;
use crate::models::{GeoIpData, Indicator, IocType};

/// GeoIP enrichment provider using MaxMind databases
pub struct GeoIpProvider {
    city_reader: Option<Arc<Reader<Vec<u8>>>>,
    asn_reader: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoIpProvider {
    /// Create a new GeoIP provider
    pub fn new(city_db_path: Option<&Path>, asn_db_path: Option<&Path>) -> Result<Self> {
        let city_reader = if let Some(path) = city_db_path {
            if path.exists() {
                Some(Arc::new(
                    Reader::open_readfile(path)
                        .context("Failed to open GeoIP city database")?
                ))
            } else {
                tracing::warn!("GeoIP city database not found at {:?}", path);
                None
            }
        } else {
            None
        };

        let asn_reader = if let Some(path) = asn_db_path {
            if path.exists() {
                Some(Arc::new(
                    Reader::open_readfile(path)
                        .context("Failed to open GeoIP ASN database")?
                ))
            } else {
                tracing::warn!("GeoIP ASN database not found at {:?}", path);
                None
            }
        } else {
            None
        };

        Ok(Self {
            city_reader,
            asn_reader,
        })
    }

    /// Lookup GeoIP data for an IP address
    pub fn lookup(&self, ip: &str) -> Result<GeoIpData> {
        let ip_addr: IpAddr = ip.parse().context("Invalid IP address")?;
        let mut data = GeoIpData::default();

        // City lookup
        if let Some(ref reader) = self.city_reader {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip_addr) {
                if let Some(country) = city.country {
                    data.country_code = country.iso_code.map(|s| s.to_string());
                    data.country_name = country.names
                        .and_then(|n| n.get("en").map(|s| s.to_string()));
                }
                
                if let Some(city_data) = city.city {
                    data.city = city_data.names
                        .and_then(|n| n.get("en").map(|s| s.to_string()));
                }

                if let Some(subdivisions) = city.subdivisions {
                    if let Some(region) = subdivisions.first() {
                        data.region = region.names
                            .as_ref()
                            .and_then(|n| n.get("en").map(|s| s.to_string()));
                    }
                }

                if let Some(location) = city.location {
                    data.latitude = location.latitude;
                    data.longitude = location.longitude;
                }
            }
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader {
            if let Ok(asn) = reader.lookup::<geoip2::Asn>(ip_addr) {
                data.asn = asn.autonomous_system_number;
                data.as_org = asn.autonomous_system_organization.map(|s| s.to_string());
            }
        }

        Ok(data)
    }
}

#[async_trait]
impl EnrichmentProvider for GeoIpProvider {
    fn name(&self) -> &'static str {
        "maxmind"
    }

    fn enrichment_type(&self) -> &'static str {
        "geoip"
    }

    fn supports(&self, ioc_type: &IocType) -> bool {
        matches!(ioc_type, IocType::Ip)
    }

    async fn enrich(&self, indicator: &Indicator) -> Result<Option<Value>> {
        if self.city_reader.is_none() && self.asn_reader.is_none() {
            return Ok(None);
        }

        let data = self.lookup(&indicator.value)?;
        
        // Only return if we got some data
        if data.country_code.is_none() && data.asn.is_none() {
            return Ok(None);
        }

        Ok(Some(json!({
            "country_code": data.country_code,
            "country_name": data.country_name,
            "city": data.city,
            "region": data.region,
            "latitude": data.latitude,
            "longitude": data.longitude,
            "asn": data.asn,
            "as_org": data.as_org,
        })))
    }

    fn ttl_hours(&self) -> i64 {
        168 // 1 week - GeoIP data doesn't change often
    }
}
