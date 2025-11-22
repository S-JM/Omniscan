/// DNS Zone Transfer (AXFR) module
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::IpAddr;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::{RecordType, RData};
use colored::*;

/// Discovered DNS record from zone transfer
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
}

/// Attempt zone transfer on a domain
/// Returns discovered records and a list of discovered hostnames/IPs
pub async fn attempt_zone_transfer(
    domain: &str,
    output_dir: &str,
    verbose: bool,
) -> Result<(Vec<ZoneRecord>, Vec<String>)> {
    if verbose {
        eprintln!("[VERBOSE] Starting zone transfer for domain: {}", domain);
    }
    
    println!("{} {}", "Attempting zone transfer for:".blue(), domain);
    
    // Create resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    
    // Get nameservers for the domain
    if verbose {
        eprintln!("[VERBOSE] Querying NS records for {}", domain);
    }
    
    let ns_lookup = match resolver.ns_lookup(domain).await {
        Ok(lookup) => lookup,
        Err(e) => {
            eprintln!("{} Failed to lookup nameservers for {}: {}", "✗".red(), domain, e);
            return Ok((Vec::new(), Vec::new()));
        }
    };
    
    let nameservers: Vec<String> = ns_lookup
        .iter()
        .map(|ns| ns.0.to_utf8())
        .collect();
    
    if nameservers.is_empty() {
        eprintln!("{} No nameservers found for {}", "✗".red(), domain);
        return Ok((Vec::new(), Vec::new()));
    }
    
    println!("  Found {} nameserver(s): {:?}", nameservers.len(), nameservers);
    
    let mut all_records = Vec::new();
    let mut discovered_hosts = HashSet::new();
    
    // Try zone transfer on each nameserver
    for ns in &nameservers {
        if verbose {
            eprintln!("[VERBOSE] Attempting AXFR on nameserver: {}", ns);
        }
        
        println!("  Trying nameserver: {}", ns);
        
        // Resolve nameserver to IP
        let ns_ips = match resolver.lookup_ip(ns.as_str()).await {
            Ok(lookup) => lookup.iter().collect::<Vec<IpAddr>>(),
            Err(e) => {
                if verbose {
                    eprintln!("[VERBOSE] Failed to resolve nameserver {}: {}", ns, e);
                }
                continue;
            }
        };
        
        if ns_ips.is_empty() {
            continue;
        }
        
        // Try AXFR on first IP of nameserver
        let ns_ip = ns_ips[0];
        
        // Create a custom resolver pointing to this specific nameserver
        use trust_dns_resolver::config::NameServerConfig;
        use std::net::SocketAddr;
        
        let socket_addr = SocketAddr::new(ns_ip, 53);
        let name_server = NameServerConfig {
            socket_addr,
            protocol: trust_dns_resolver::config::Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        };
        
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(name_server);
        
        let ns_resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
        
        // Attempt AXFR query
        match ns_resolver.lookup(domain, RecordType::AXFR).await {
            Ok(lookup) => {
                let record_count = lookup.record_iter().count();
                
                if record_count == 0 {
                    println!("    {} Zone transfer denied or no records", "✗".yellow());
                    continue;
                }
                
                println!("    {} Zone transfer successful! Found {} records", "✓".green(), record_count);
                
                // Parse records
                for record in lookup.record_iter() {
                    let name = record.name().to_utf8();
                    let rdata = record.data();
                    
                    let (record_type, value) = match rdata {
                        Some(RData::A(ip)) => {
                            discovered_hosts.insert(ip.to_string());
                            ("A".to_string(), ip.to_string())
                        },
                        Some(RData::AAAA(ip)) => {
                            discovered_hosts.insert(ip.to_string());
                            ("AAAA".to_string(), ip.to_string())
                        },
                        Some(RData::CNAME(cname)) => {
                            let cname_str = cname.to_utf8();
                            discovered_hosts.insert(cname_str.clone());
                            ("CNAME".to_string(), cname_str)
                        },
                        Some(RData::MX(mx)) => {
                            let mx_str = mx.exchange().to_utf8();
                            discovered_hosts.insert(mx_str.clone());
                            ("MX".to_string(), format!("{} {}", mx.preference(), mx_str))
                        },
                        Some(RData::NS(ns)) => {
                            ("NS".to_string(), ns.0.to_utf8())
                        },
                        Some(RData::TXT(txt)) => {
                            let txt_data = txt.iter()
                                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                                .collect::<Vec<_>>()
                                .join(" ");
                            ("TXT".to_string(), txt_data)
                        },
                        Some(RData::SOA(soa)) => {
                            ("SOA".to_string(), format!("{} {}", soa.mname().to_utf8(), soa.rname().to_utf8()))
                        },
                        _ => continue,
                    };
                    
                    all_records.push(ZoneRecord {
                        name: name.clone(),
                        record_type,
                        value,
                    });
                }
                
                // Successfully got zone transfer, no need to try other nameservers
                break;
            },
            Err(e) => {
                if verbose {
                    eprintln!("[VERBOSE] AXFR failed on {}: {}", ns, e);
                }
                println!("    {} Zone transfer denied or failed", "✗".yellow());
            }
        }
    }
    
    // Save results to file if we got any records
    if !all_records.is_empty() {
        save_zone_transfer_results(domain, &all_records, output_dir)?;
    }
    
    let discovered_list: Vec<String> = discovered_hosts.into_iter().collect();
    
    Ok((all_records, discovered_list))
}

/// Save zone transfer results to file
fn save_zone_transfer_results(
    domain: &str,
    records: &[ZoneRecord],
    output_dir: &str,
) -> Result<()> {
    use std::fs;
    use std::io::Write;
    
    // Ensure output directory exists
    if !std::path::Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    }
    
    let safe_domain = domain.replace(":", "_").replace("/", "_");
    let output_file = format!("{}/zone_transfer_{}.txt", output_dir, safe_domain);
    
    let mut file = fs::File::create(&output_file)
        .context(format!("Failed to create file: {}", output_file))?;
    
    writeln!(file, "DNS Zone Transfer Results for: {}", domain)?;
    writeln!(file, "=")?;
    writeln!(file)?;
    
    for record in records {
        writeln!(file, "{:<40} {:<10} {}", record.name, record.record_type, record.value)?;
    }
    
    println!("{} {} records to: {}", "✓ Saved".green(), records.len(), output_file);
    
    Ok(())
}

/// Run zone transfers on all provided domains
pub async fn run_zone_transfers(
    domains: &[String],
    output_dir: &str,
    verbose: bool,
) -> Result<Vec<String>> {
    if domains.is_empty() {
        return Ok(Vec::new());
    }
    
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  DNS ZONE TRANSFER".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Attempting zone transfers on {} domain(s)", domains.len());
    println!("{}", "-".repeat(70));
    
    let mut all_discovered = Vec::new();
    
    for domain in domains {
        let (records, discovered) = attempt_zone_transfer(domain, output_dir, verbose).await?;
        
        if !records.is_empty() {
            println!("{} Discovered {} unique hosts/IPs from zone transfer", "✓".green(), discovered.len());
            all_discovered.extend(discovered);
        }
        
        println!();
    }
    
    println!("{}", "=".repeat(70).blue().bold());
    println!("{}", "  ZONE TRANSFER COMPLETE".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    
    if !all_discovered.is_empty() {
        println!("Total discovered hosts: {}", all_discovered.len());
    }
    
    Ok(all_discovered)
}
