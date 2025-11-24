use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

use crate::target::Target;
use crate::utils;
use tokio_util::sync::CancellationToken;
use colored::*;

/// Performs subdomain fuzzing on Domain targets.
///
/// Uses a wordlist to generate potential subdomains and resolves them.
/// Returns a list of discovered subdomains that resolve to IPs matching the initial targets.
/// Saves matching subdomains to `found_subdomains.txt` in the output directory.
pub async fn fuzz_subdomains(
    targets: &[Target],
    wordlist_path: &str,
    output_dir: &str,
    verbose: bool,
    cancel_token: CancellationToken,
) -> Result<Vec<String>> {
    if verbose {
        eprintln!("[VERBOSE] Initializing subdomain fuzzer");
    }

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
        if verbose {
            eprintln!("[VERBOSE] No domains to fuzz, skipping");
        }
        return Ok(vec![]);
    }

    if verbose {
        eprintln!("[VERBOSE] Fuzzing subdomains for: {:?}", domains);
    }
    println!("{} {:?}", "Fuzzing subdomains for:".blue(), domains);

    let wordlist = utils::read_lines(wordlist_path).context("Failed to read wordlist")?;
    if verbose {
        eprintln!("[VERBOSE] Loaded {} words from wordlist", wordlist.len());
    }
    let mut valid_subdomains: Vec<(String, Vec<IpAddr>)> = Vec::new();

    // Create a stream of tasks to resolve subdomains concurrently
    let mut tasks = Vec::new();
    for domain in &domains {
        for word in &wordlist {
            let subdomain = format!("{}.{}", word, domain);
            let resolver = resolver.clone();
            let subdomain_clone = subdomain.clone();
            
            tasks.push(async move {
                // Small delay to avoid overwhelming DNS server
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                
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

    // Run up to 20 concurrent lookups (reduced from 100 to avoid DNS throttling)
    let mut stream = stream::iter(tasks).buffer_unordered(20);

    let total_checks = wordlist.len() * domains.len();
    let mut checked = 0;
    let mut last_update = std::time::Instant::now();
    let update_interval = std::time::Duration::from_secs(5);

    if verbose {
        eprintln!("[VERBOSE] Starting DNS lookups with concurrency=20 and 10ms delay per request");
    }
    println!("{} {} total subdomain checks", "Starting fuzzing:".blue(), total_checks);

    while let Some(result) = stream.next().await {
        // Check for cancellation
        if cancel_token.is_cancelled() {
            println!("\n\n{}", "Fuzzing cancelled. Returning partial results...".red());
            break;
        }
        
        checked += 1;

        // Print status update every 5 seconds (on same line)
        if last_update.elapsed() >= update_interval {
            use std::io::{self, Write};
            let progress_pct = (checked as f64 / total_checks as f64 * 100.0) as u32;
            print!("\rFuzzing progress: {}/{} checked ({}%), {} matches found   ", 
                     checked, total_checks, progress_pct, valid_subdomains.len());
            io::stdout().flush().ok();
            last_update = std::time::Instant::now();
        }

        if let Some((subdomain, ips)) = result {
            // Check if any of the resolved IPs match our target IPs/Networks
            let mut matched_ips = Vec::new();
            for ip in &ips {
                for target in targets {
                    match target {
                        Target::IP(target_ip) => {
                            if ip == target_ip {
                                matched_ips.push(*ip);
                                break;
                            }
                        }
                        Target::Network(network) => {
                            if network.contains(*ip) {
                                matched_ips.push(*ip);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            if !matched_ips.is_empty() {
                // Clear the progress line before printing the match
                print!("\r{}\r", " ".repeat(80));
                println!("{} {} -> {:?}", "✓ Found valid subdomain:".green(), subdomain, matched_ips);
                valid_subdomains.push((subdomain, matched_ips));
            }
        }
    }

    println!("\r{} {}/{} checked, {} matches found   ", 
             "Fuzzing complete:".green(), checked, total_checks, valid_subdomains.len());

    // Write found subdomains to file
    if !valid_subdomains.is_empty() {
        use std::fs;
        use std::io::Write;
        
        // Ensure output directory exists
        if !std::path::Path::new(output_dir).exists() {
            fs::create_dir_all(output_dir).context("Failed to create output directory")?;
        }
        
        let output_file = format!("{}/found_subdomains.txt", output_dir);
        let mut file = fs::File::create(&output_file)
            .context(format!("Failed to create file: {}", output_file))?;
        
        for (subdomain, ips) in &valid_subdomains {
            let ips_str = ips.iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(file, "{}: {}", subdomain, ips_str)?;
        }
        
        println!("{} {} subdomains to: {}", "✓ Saved".green(), valid_subdomains.len(), output_file);
    }

    // Convert to Vec<String> for return (keeping subdomain names only for backward compatibility)
    let subdomain_names: Vec<String> = valid_subdomains.iter()
        .map(|(subdomain, _)| subdomain.clone())
        .collect();

    Ok(subdomain_names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_extract_domains_from_targets() {
        let targets = vec![
            Target::Domain("example.com".to_string()),
            Target::IP("192.168.1.1".parse().unwrap()),
            Target::Domain("test.org".to_string()),
            Target::Network("10.0.0.0/24".parse().unwrap()),
        ];

        let domains: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"test.org".to_string()));
    }

    #[test]
    fn test_extract_domains_no_domains() {
        let targets = vec![
            Target::IP("192.168.1.1".parse().unwrap()),
            Target::Network("10.0.0.0/24".parse().unwrap()),
        ];

        let domains: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(domains.len(), 0);
    }

    #[test]
    fn test_extract_domains_only_domains() {
        let targets = vec![
            Target::Domain("example.com".to_string()),
            Target::Domain("test.org".to_string()),
            Target::Domain("demo.net".to_string()),
        ];

        let domains: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();

        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn test_subdomain_generation() {
        let domain = "example.com";
        let word = "www";
        let subdomain = format!("{}.{}", word, domain);
        assert_eq!(subdomain, "www.example.com");
    }

    #[test]
    fn test_ip_matching_logic() {
        let target_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let resolved_ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(target_ip, resolved_ip);
    }

    #[test]
    fn test_network_contains_ip() {
        let network: ipnetwork::IpNetwork = "192.168.1.0/24".parse().unwrap();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert!(network.contains(ip));
    }

    #[test]
    fn test_network_does_not_contain_ip() {
        let network: ipnetwork::IpNetwork = "192.168.1.0/24".parse().unwrap();
        let ip: IpAddr = "192.168.2.100".parse().unwrap();
        assert!(!network.contains(ip));
    }
}
