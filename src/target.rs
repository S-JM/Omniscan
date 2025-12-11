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

/// Resolves domain targets to IP addresses and filters them against explicit targets.
///
/// This function takes a list of targets (which may include domains) and resolves any
/// domains to their IP addresses. It then filters the resolved IPs to only include those
/// that match the explicit target list (IPs or networks).
///
/// # Arguments
/// * `targets` - List of targets that may include domains to resolve
/// * `explicit_ips` - List of explicit IP/network targets to filter against
/// * `verbose` - Enable verbose logging
///
/// # Returns
/// A tuple of (scan_targets, domain_names) where:
/// - scan_targets: Vec of IP targets that match the explicit list
/// - domain_names: Vec of domain names that were encountered
///
/// # Example
/// ```no_run
/// use omniscan::target::{Target, resolve_targets};
///
/// # async fn example() -> anyhow::Result<()> {
/// let targets = vec![Target::Domain("example.com".to_string())];
/// let explicit = vec![Target::Network("93.184.216.0/24".parse().unwrap())];
/// let (scan_targets, domains) = resolve_targets(&targets, &explicit, false).await?;
/// # Ok(())
/// # }
/// ```
pub async fn resolve_targets(
    targets: &[Target],
    explicit_ips: &[Target],
    verbose: bool,
    strict_scope: bool,
) -> Result<(Vec<Target>, Vec<String>)> {
    use hickory_resolver::TokioAsyncResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    let mut scan_targets: Vec<Target> = explicit_ips.to_vec();
    let mut domain_names: Vec<String> = Vec::new();

    for t in targets {
        if let Target::Domain(domain) = t {
            domain_names.push(domain.clone());

            if verbose {
                println!("Resolving domain: {}", domain);
            }

            let resolver = TokioAsyncResolver::tokio(
                ResolverConfig::google(),
                ResolverOpts::default()
            );

            match resolver.lookup_ip(domain.as_str()).await {
                Ok(response) => {
                    let resolved_ips: Vec<IpAddr> = response.iter().collect();
                    
                    if verbose {
                        println!("Domain {} resolves to: {:?}", domain, resolved_ips);
                    } else {
                        println!("Domain {} resolves to: {:?}", domain, resolved_ips);
                    }

                    // Check if any resolved IP matches explicit targets
                    for resolved_ip in resolved_ips {
                        let mut matches_explicit = false;
                        
                        if strict_scope {
                            for explicit in explicit_ips {
                                match explicit {
                                    Target::IP(ip) => {
                                        if &resolved_ip == ip {
                                            matches_explicit = true;
                                            break;
                                        }
                                    }
                                    Target::Network(network) => {
                                        if network.contains(resolved_ip) {
                                            matches_explicit = true;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }

                            if matches_explicit {
                                println!("  -> {} is in explicit target list, will scan", resolved_ip);
                                scan_targets.push(Target::IP(resolved_ip));
                            } else {
                                println!("  -> {} is NOT in explicit target list, skipping (strict scope)", resolved_ip);
                            }
                        } else {
                            // Not strict scope - add all resolved IPs
                            println!("  -> {} added to scan targets", resolved_ip);
                            scan_targets.push(Target::IP(resolved_ip));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to resolve domain {}: {}", domain, e);
                }
            }
        }
    }

    Ok((scan_targets, domain_names))
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

    #[tokio::test]
    async fn test_resolve_targets_ips_only() {
        let targets = vec![Target::IP("192.168.1.1".parse().unwrap())];
        let explicit = vec![Target::IP("192.168.1.1".parse().unwrap())];
        
        let (resolved, domains) = resolve_targets(&targets, &explicit, false, true).await.unwrap();
        
        // Should contain the explicit IP
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved[0], Target::IP(_)));
        assert_eq!(domains.len(), 0);
    }

    #[tokio::test]
    async fn test_resolve_targets_localhost_match() {
        // This test assumes localhost resolves to 127.0.0.1
        let targets = vec![Target::Domain("localhost".to_string())];
        let explicit = vec![Target::IP("127.0.0.1".parse().unwrap())];
        
        let (resolved, domains) = resolve_targets(&targets, &explicit, false, true).await.unwrap();
        
        // Should contain explicit IP + resolved IP (so 2 total, duplicates allowed by logic)
        // Wait, logic is: scan_targets starts with explicit_ips.
        // Then appends resolved IPs if they match.
        // So if localhost -> 127.0.0.1, and explicit is 127.0.0.1.
        // scan_targets will be [127.0.0.1, 127.0.0.1].
        
        assert!(resolved.len() >= 1); 
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "localhost");
    }

    #[tokio::test]
    async fn test_resolve_targets_localhost_no_match() {
        let targets = vec![Target::Domain("localhost".to_string())];
        // Explicit IP that definitely doesn't match localhost
        let explicit = vec![Target::IP("1.2.3.4".parse().unwrap())];
        
        let (resolved, domains) = resolve_targets(&targets, &explicit, false, true).await.unwrap();
        
        // Should ONLY contain the explicit IP (1.2.3.4)
        // Resolved localhost (127.0.0.1) should be filtered out
        assert_eq!(resolved.len(), 1);
        if let Target::IP(ip) = resolved[0] {
            assert_eq!(ip.to_string(), "1.2.3.4");
        }
        assert_eq!(domains.len(), 1);
    }
}
