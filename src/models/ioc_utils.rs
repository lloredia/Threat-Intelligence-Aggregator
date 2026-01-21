// src/models/ioc_utils.rs

use crate::models::IocType;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Detect the IOC type from a raw value string
pub fn detect_ioc_type(value: &str) -> Option<IocType> {
    let trimmed = value.trim();
    
    if trimmed.is_empty() {
        return None;
    }
    
    // CVE pattern (e.g., CVE-2021-44228)
    if trimmed.to_uppercase().starts_with("CVE-") {
        return Some(IocType::Cve);
    }
    
    // Hash patterns (MD5=32, SHA1=40, SHA256=64 hex chars)
    if (trimmed.len() == 32 || trimmed.len() == 40 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Some(IocType::Hash);
    }
    
    // URL pattern
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(IocType::Url);
    }
    
    // Email pattern
    if trimmed.contains('@') && trimmed.contains('.') {
        return Some(IocType::Email);
    }
    
    // IPv4 pattern
    if trimmed.parse::<Ipv4Addr>().is_ok() {
        return Some(IocType::Ip);
    }
    
    // IPv6 pattern
    if trimmed.parse::<Ipv6Addr>().is_ok() {
        return Some(IocType::Ip);
    }
    
    // CIDR patterns (treat as IP)
    if trimmed.contains('/') {
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.len() == 2 {
            if parts[0].parse::<Ipv4Addr>().is_ok() || parts[0].parse::<Ipv6Addr>().is_ok() {
                return Some(IocType::Ip);
            }
        }
    }
    
    // Domain pattern
    if trimmed.contains('.') 
        && !trimmed.contains(' ') 
        && !trimmed.contains('/') 
        && !trimmed.contains('@')
        && trimmed.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        return Some(IocType::Domain);
    }
    
    None
}

/// Normalize an IOC value based on its type
pub fn normalize_ioc(value: &str, ioc_type: &IocType) -> String {
    let trimmed = value.trim();
    
    match ioc_type {
        IocType::Domain => trimmed.to_lowercase(),
        IocType::Url => {
            if let Some(idx) = trimmed.find("://") {
                let (scheme, rest) = trimmed.split_at(idx + 3);
                if let Some(path_idx) = rest.find('/') {
                    let (host, path) = rest.split_at(path_idx);
                    format!("{}{}{}", scheme.to_lowercase(), host.to_lowercase(), path)
                } else {
                    trimmed.to_lowercase()
                }
            } else {
                trimmed.to_lowercase()
            }
        }
        IocType::Email => trimmed.to_lowercase(),
        IocType::Ip => trimmed.to_lowercase(),
        IocType::Hash => trimmed.to_lowercase(),
        IocType::Cve => trimmed.to_uppercase(),
    }
}