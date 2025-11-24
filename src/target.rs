use anyhow::Result;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::str::FromStr;

/// Represents a scan target.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    IP(IpAddr),
    Network(IpNetwork),
    Domain(String),
}

/// Parses a list of target strings into `Target` enums.
///
/// Supports IPs (v4/v6), CIDRs, and Domain names.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_address() {
        let input = vec!["192.168.1.1".to_string()];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], Target::IP(_)));
    }

    #[test]
    fn test_parse_ipv6_address() {
        let input = vec!["::1".to_string()];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], Target::IP(_)));
    }

    #[test]
    fn test_parse_cidr_network() {
        let input = vec!["10.0.0.0/24".to_string()];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0], Target::Network(_)));
    }

    #[test]
    fn test_parse_domain() {
        let input = vec!["example.com".to_string()];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 1);
        match &targets[0] {
            Target::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("Expected Domain variant"),
        }
    }

    #[test]
    fn test_parse_mixed_targets() {
        let input = vec![
            "192.168.1.1".to_string(),
            "10.0.0.0/24".to_string(),
            "example.com".to_string(),
            "::1".to_string(),
        ];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 4);
    }

    #[test]
    fn test_parse_empty_input() {
        let input = vec![];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 0);
    }

    #[test]
    fn test_parse_with_whitespace() {
        let input = vec![
            "  192.168.1.1  ".to_string(),
            " example.com ".to_string(),
        ];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_parse_skips_empty_strings() {
        let input = vec![
            "192.168.1.1".to_string(),
            "".to_string(),
            "   ".to_string(),
            "example.com".to_string(),
        ];
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_target_equality() {
        let ip1 = Target::IP("192.168.1.1".parse().unwrap());
        let ip2 = Target::IP("192.168.1.1".parse().unwrap());
        assert_eq!(ip1, ip2);
    }
}
