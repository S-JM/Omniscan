use clap::Parser;
use anyhow::Result;
use nmap_helper::target;
use nmap_helper::scanner;
use nmap_helper::fuzzer;
use nmap_helper::utils;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of targets (IPs, CIDRs, or Domains)
    #[arg(required = false)]
    targets: Vec<String>,

    /// Input file containing targets (one per line)
    #[arg(short, long)]
    input_file: Option<String>,

    /// Path to subdomain wordlist (required if domains are present)
    #[arg(long)]
    wordlist: Option<String>,

    /// Directory for scan results
    #[arg(long, default_value = ".")]
    output_dir: String,

    /// Dry run mode: print commands without executing them
    #[arg(long)]
    dry_run: bool,

    /// Verbose mode: print debug messages
    #[arg(short, long)]
    verbose: bool,

    /// Output all formats (XML, normal, grepable) instead of just XML
    #[arg(long)]
    all_formats: bool,

    /// Run testssl.sh on discovered SSL/TLS services
    #[arg(long)]
    testssl: bool,

    /// Run ONLY testssl.sh on all provided targets (skips Nmap scans).
    /// NOTE: This bypasses strict scoping rules - all provided domains and IPs will be scanned.
    #[arg(long)]
    testssl_only: bool,

    /// Skip subdomain fuzzing
    #[arg(long)]
    skip_fuzzing: bool,

    /// Automatically answer yes to all prompts
    #[arg(long)]
    yes_all: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut all_targets_str = Vec::new();

    // Add targets from CLI args
    all_targets_str.extend(args.targets);

    // Add targets from input file
    if let Some(input_file) = args.input_file {
        let lines = utils::read_lines(&input_file)?;
        all_targets_str.extend(lines);
    }

    if all_targets_str.is_empty() {
        eprintln!("No targets provided. Use --help for usage information.");
        return Ok(());
    }


    let targets = target::parse_targets(all_targets_str)?;

    println!("Parsed {} targets:", targets.len());
    for t in &targets {
        println!("{:?}", t);
    }

    // Extract explicit IP addresses and CIDR ranges (not domains)
    let explicit_ips: Vec<target::Target> = targets
        .iter()
        .filter(|t| !matches!(t, target::Target::Domain(_)))
        .cloned()
        .collect();

    // Resolve domain names and filter to only those resolving to explicit IPs
    let mut scan_targets: Vec<target::Target> = explicit_ips.clone();
    
    for t in &targets {
        if let target::Target::Domain(domain) = t {
            // Resolve domain
            use trust_dns_resolver::TokioAsyncResolver;
            use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
            
            let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
            match resolver.lookup_ip(domain.as_str()).await {
                Ok(response) => {
                    let resolved_ips: Vec<std::net::IpAddr> = response.iter().collect();
                    println!("Domain {} resolves to: {:?}", domain, resolved_ips);
                    
                    // Check if any resolved IP matches explicit targets
                    for resolved_ip in resolved_ips {
                        let mut matches_explicit = false;
                        for explicit in &explicit_ips {
                            match explicit {
                                target::Target::IP(ip) => {
                                    if &resolved_ip == ip {
                                        matches_explicit = true;
                                        break;
                                    }
                                }
                                target::Target::Network(network) => {
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
                            scan_targets.push(target::Target::IP(resolved_ip));
                        } else {
                            println!("  -> {} is NOT in explicit target list, skipping", resolved_ip);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to resolve domain {}: {}", domain, e);
                }
            }
        }
    }

    println!("\nFinal scan targets: {} IPs/CIDRs", scan_targets.len());


    // Always show a preview of what will be done
    println!("\n{}", "=".repeat(70));
    println!("  PREVIEW: Commands that will be executed");
    println!("{}", "=".repeat(70));
    
    // Show fuzzing preview if applicable
    if args.wordlist.is_some() {
        let domain_targets: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                target::Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        
        if !domain_targets.is_empty() {
            println!("\n# Subdomain Fuzzing");
            println!("Wordlist: {}", args.wordlist.as_ref().unwrap());
            println!("Domains to fuzz: {:?}", domain_targets);
        }
    }
    
    // Show scan preview by calling run_scans in dry-run mode
    if !args.testssl_only {
        scanner::run_scans(&scan_targets, &args.output_dir, true, args.verbose, args.all_formats, args.testssl, args.yes_all).await?;
    } else {
        println!("\n# Nmap Scans");
        println!("Skipped (--testssl-only)");
        
        println!("\n# TestSSL.sh Scan");
        println!("Will run testssl.sh on all provided targets (domains and IPs)");
        if args.wordlist.is_some() {
            println!("And on any subdomains found via fuzzing");
        }
    }
    
    // If --dry-run flag is set, exit here
    if args.dry_run {
        return Ok(());
    }
    
    // Ask user for confirmation (unless --yes-all is set)
    if args.yes_all {
        println!("\n{}", "=".repeat(70));
        println!("  AUTO-CONFIRMED (--yes-all)");
        println!("{}", "=".repeat(70));
    } else {
        println!("\n{}", "=".repeat(70));
        print!("Do you want to proceed with execution? [y/N]: ");
        use std::io::{self, Write};
        io::stdout().flush()?;
        
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();
        
        if response != "y" && response != "yes" {
            println!("Execution aborted by user.");
            return Ok(());
        }
    }
    
    println!("\n{}", "=".repeat(70));
    println!("  EXECUTION STARTED");
    println!("{}", "=".repeat(70));
    
    // Run actual fuzzing if wordlist provided and not skipped
    let mut fuzzed_subdomains = Vec::new();
    if let Some(wordlist) = &args.wordlist {
        if args.skip_fuzzing {
            println!("\n{}", "=".repeat(70));
            println!("  SUBDOMAIN FUZZING - SKIPPED (--skip-fuzzing)");
            println!("{}", "=".repeat(70));
        } else {
            println!("\n{}", "=".repeat(70));
            println!("  SUBDOMAIN FUZZING");
            println!("{}", "=".repeat(70));
            
            // Create a cancellation token for Ctrl-C handling
            use tokio_util::sync::CancellationToken;
            let cancel_token = CancellationToken::new();
            let cancel_token_clone = cancel_token.clone();
            
            // Spawn a task to listen for Ctrl-C
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                cancel_token_clone.cancel();
            });
            
            // Run fuzzing with cancellation support
            // Note: fuzzer::fuzz_subdomains handles the cancellation token internally
            // and returns partial results if cancelled.
            match fuzzer::fuzz_subdomains(&targets, wordlist, &args.output_dir, args.verbose, cancel_token.clone()).await {
                Ok(found) => {
                    fuzzed_subdomains = found;
                    if !fuzzed_subdomains.is_empty() {
                        println!("Found {} valid subdomains:", fuzzed_subdomains.len());
                        for d in &fuzzed_subdomains {
                            println!("{}", d);
                        }
                        
                        // Add to scan targets
                        println!("Adding found subdomains to scan targets...");
                        for sub in &fuzzed_subdomains {
                            scan_targets.push(target::Target::Domain(sub.clone()));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Fuzzing error: {}", e);
                }
            }
        }
    }
    
    
    // Pass scan targets (filtered IPs only) to scanner for actual execution
    // If --testssl-only is set, skip Nmap scans
    let ssl_info = if !args.testssl_only {
        scanner::run_scans(&scan_targets, &args.output_dir, false, args.verbose, args.all_formats, args.testssl, args.yes_all).await?
    } else {
        println!("\n{}", "=".repeat(70));
        println!("  NMAP SCANS - SKIPPED (--testssl-only)");
        println!("{}", "=".repeat(70));
        Vec::new()
    };
    
    // Run testssl.sh if enabled (either via --testssl or --testssl-only)
    if args.testssl || args.testssl_only {
        // Collect domain targets from original input
        let mut domain_targets: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                target::Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
            
        // If testssl-only is set, also add all provided IPs to the target list
        // This bypasses the strict scoping rule used for Nmap scans
        if args.testssl_only {
            for t in &targets {
                if let target::Target::IP(ip) = t {
                    domain_targets.push(ip.to_string());
                }
            }
        }
            
        // Add fuzzed subdomains to TestSSL targets
        if !fuzzed_subdomains.is_empty() {
            domain_targets.extend(fuzzed_subdomains.clone());
        }
        
        // ssl_info contains (ip, port) pairs for discovered SSL services
        nmap_helper::ssl_scanner::run_testssl_scans(&domain_targets, &ssl_info, &args.output_dir).await?;
    }
    
    Ok(())
}
