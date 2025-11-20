use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

use crate::target::Target;
use crate::utils;

/// Performs subdomain fuzzing on Domain targets.
///
/// Uses a wordlist to generate potential subdomains and resolves them.
/// Returns a list of discovered subdomains that resolve to IPs matching the initial targets.
pub async fn fuzz_subdomains(
    targets: &[Target],
    wordlist_path: &str,
) -> Result<Vec<String>> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    let resolver = Arc::new(resolver);

    // Extract domains from targets
    let domains: Vec<String> = targets
        .iter()
        .filter_map(|t| match t {
            Target::Domain(d) => Some(d.clone()),
            _ => None,
        })
        .collect();

    if domains.is_empty() {
        return Ok(vec![]);
    }

    println!("Fuzzing subdomains for: {:?}", domains);

    let wordlist = utils::read_lines(wordlist_path).context("Failed to read wordlist")?;
    let mut valid_subdomains = Vec::new();

    // Create a stream of tasks to resolve subdomains concurrently
    let mut tasks = Vec::new();
    for domain in &domains {
        for word in &wordlist {
            let subdomain = format!("{}.{}", word, domain);
            let resolver = resolver.clone();
            let subdomain_clone = subdomain.clone();
            
            tasks.push(async move {
                match resolver.lookup_ip(&subdomain_clone).await {
                    Ok(response) => {
                        let ips: Vec<IpAddr> = response.iter().collect();
                        Some((subdomain_clone, ips))
                    }
                    Err(_) => None,
                }
            });
        }
    }

    // Run up to 100 concurrent lookups
    let mut stream = stream::iter(tasks).buffer_unordered(100);

    while let Some(result) = stream.next().await {
        if let Some((subdomain, ips)) = result {
            // Check if any of the resolved IPs match our target IPs/Networks
            let mut matched = false;
            for ip in ips {
                for target in targets {
                    match target {
                        Target::IP(target_ip) => {
                            if &ip == target_ip {
                                matched = true;
                                break;
                            }
                        }
                        Target::Network(network) => {
                            if network.contains(ip) {
                                matched = true;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if matched {
                    break;
                }
            }

            if matched {
                println!("Found valid subdomain: {}", subdomain);
                valid_subdomains.push(subdomain);
            }
        }
    }

    Ok(valid_subdomains)
}
