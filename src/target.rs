use anyhow::Result;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    IP(IpAddr),
    Network(IpNetwork),
    Domain(String),
}

pub fn parse_targets(input: Vec<String>) -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    for item in input {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        if let Ok(ip) = IpAddr::from_str(item) {
            targets.push(Target::IP(ip));
        } else if let Ok(network) = IpNetwork::from_str(item) {
            targets.push(Target::Network(network));
        } else {
            // Assume it's a domain if it's not an IP or CIDR
            targets.push(Target::Domain(item.to_string()));
        }
    }

    Ok(targets)
}
