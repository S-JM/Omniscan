use clap::Parser;
use anyhow::Result;
use omniscan::target;
use omniscan::scanner;
use omniscan::fuzzer;
use omniscan::utils;
use omniscan::zone_transfer;
use omniscan::email_verification;
use omniscan::crt_sh;
use omniscan::config::ScanConfig;
use omniscan::interactive;
use colored::*;

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

    /// Run ONLY DNS zone transfer on all provided domains (skips Nmap, fuzzing, TestSSL).
    #[arg(long)]
    zone_transfer_only: bool,

    /// Run ONLY email DNS verification on all provided domains (skips Nmap, fuzzing, TestSSL, zone transfer).
    #[arg(long)]
    email_verification_only: bool,

    /// Check crt.sh for subdomains
    #[arg(long)]
    crt_sh: bool,

    /// Run ONLY crt.sh subdomain enumeration on all provided domains (skips Nmap, fuzzing, TestSSL, zone transfer, email).
    #[arg(long)]
    crt_sh_only: bool,
}

impl From<Args> for ScanConfig {
    fn from(args: Args) -> Self {
        let mut config = ScanConfig {
            targets: args.targets,
            output_dir: args.output_dir,
            dry_run: args.dry_run,
            verbose: args.verbose,
            all_formats: args.all_formats,
            yes_all: args.yes_all,
            wordlist: args.wordlist,
            strict_scope: true, // CLI always defaults to strict scope for backward compatibility
            
            // Initialize explicit flags based on CLI args
            run_port_scan: false,
            run_testssl: false,
            run_fuzzing: false,
            run_zone_transfer: false,
            run_email_verification: false,
            run_crt_sh: false,

            custom_nmap_args: None,
            firewall_evasion: false,
        };

        // Logic to map CLI args to explicit flags
        if args.testssl_only {
            config.run_testssl = true;
            // strict_scope is bypassed for testssl_only in the original logic, 
            // but we'll keep it true here and handle the target selection logic in main.rs
        } else if args.zone_transfer_only {
            config.run_zone_transfer = true;
        } else if args.email_verification_only {
            config.run_email_verification = true;
        } else if args.crt_sh_only {
            config.run_crt_sh = true;
        } else {
            // Default behavior (Nmap + Fuzzing + Zone Transfer + Email + TestSSL if requested)
            // Wait, original behavior was:
            // Nmap: Always unless *_only
            // Fuzzing: Always unless skip_fuzzing or *_only
            // Zone Transfer: Always unless *_only
            // Email: Always unless *_only
            // TestSSL: Only if --testssl is set
            
            config.run_port_scan = true;
            config.run_zone_transfer = true;
            config.run_email_verification = true;
            
            if !args.skip_fuzzing {
                config.run_fuzzing = true;
            }
            
            if args.testssl {
                config.run_testssl = true;
            }

            if args.crt_sh {
                config.run_crt_sh = true;
            }
        }
        
        config
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check if any arguments were provided
    let has_args = std::env::args().len() > 1;

    let config = if has_args {
        let args = Args::parse();
        let mut config = ScanConfig::from(args);
        
        let args_ref = Args::parse(); // Re-parse to access input_file
        if let Some(input_file) = args_ref.input_file {
            let lines = utils::read_lines(&input_file)?;
            config.targets.extend(lines);
        }
        
        config
    } else {
        // No args, run interactive mode
        match interactive::run_interactive_menu() {
            Ok(c) => c,
            Err(e) => {
                // If error is due to interruption, handle it
                if e.to_string().contains("interrupted") || e.to_string().contains("IO error") {
                     println!("\n{}", "Interactive mode cancelled.".yellow());
                     return Ok(());
                }
                return Err(e);
            }
        }
    };

    run_scan(config).await
}

async fn run_scan(config: ScanConfig) -> Result<()> {
    if config.targets.is_empty() {
        eprintln!("{}", "No targets provided. Use --help for usage information.".red());
        return Ok(());
    }

    let targets = target::parse_targets(config.targets.clone())?;

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
    // Pass strict_scope from config
    let (mut scan_targets, domain_names) = target::resolve_targets(&targets, &explicit_ips, config.verbose, config.strict_scope).await?;


    println!("\nFinal scan targets: {} IPs/CIDRs", scan_targets.len());

    // Always show a preview of what will be done
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  PREVIEW: Commands that will be executed".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    
    // Show fuzzing preview if applicable
    if config.run_fuzzing && config.wordlist.is_some() {
        if !domain_names.is_empty() {
            println!("\n{}", "# Subdomain Fuzzing".blue().bold());
            println!("Wordlist: {}", config.wordlist.as_ref().unwrap());
            println!("Domains to fuzz: {:?}", domain_names);
        }
    } else if !config.run_fuzzing {
        println!("\n{}", "# Subdomain Fuzzing".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }
    
    // Show zone transfer preview if applicable
    if config.run_zone_transfer {
        if !domain_names.is_empty() {
            println!("\n{}", "# DNS Zone Transfer".blue().bold());
            println!("Will attempt zone transfers on {} domain(s)", domain_names.len());
            println!("Domains: {:?}", domain_names);
        }
    } else {
        println!("\n{}", "# DNS Zone Transfer".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }
    
    // Show email verification preview if applicable
    if config.run_email_verification {
        if !domain_names.is_empty() {
            println!("\n{}", "# Email DNS Verification".blue().bold());
            println!("Will verify email DNS records for {} domain(s)", domain_names.len());
            println!("Checks: SPF, DMARC, DKIM");
        }
    } else {
        println!("\n{}", "# Email DNS Verification".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }

    // Show crt.sh preview if applicable
    if config.run_crt_sh {
        if !domain_names.is_empty() {
            println!("\n{}", "# crt.sh Subdomain Enumeration".blue().bold());
            println!("Will query crt.sh for subdomains of {} domain(s)", domain_names.len());
            println!("Domains: {:?}", domain_names);
        }
    } else {
        println!("\n{}", "# crt.sh Subdomain Enumeration".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }
    
    // Show scan preview
    if config.run_port_scan {
        // Just show the header, the actual preview comes from scanner::run_scans dry run
        // But we need to call it.
        scanner::run_scans(
            &scan_targets, 
            &config.output_dir, 
            true, 
            config.verbose, 
            config.all_formats, 
            config.yes_all,
            config.custom_nmap_args.as_deref(),
            config.firewall_evasion
        ).await?;
    } else {
        println!("\n{}", "# Nmap Scans".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }

    if config.run_testssl {
        println!("\n{}", "# TestSSL.sh Scan".blue().bold());
        println!("Will run testssl.sh on all provided targets (domains and IPs)");
        if config.wordlist.is_some() && config.run_fuzzing {
            println!("And on any subdomains found via fuzzing");
        }
    } else {
        println!("\n{}", "# TestSSL.sh Scan".blue().bold());
        println!("{}", "Skipped (Not selected)".yellow());
    }
    
    // If --dry-run flag is set, exit here
    if config.dry_run {
        return Ok(());
    }
    
    // Ask user for confirmation (unless --yes-all is set)
    if config.yes_all {
        println!("\n{}", "=".repeat(70).blue().bold());
        println!("{}", "  AUTO-CONFIRMED (--yes-all)".green().bold());
        println!("{}", "=".repeat(70).blue().bold());
    } else {
        println!("\n{}", "=".repeat(70).blue().bold());
        print!("{}", "Do you want to proceed with execution? [y/N]: ".yellow().bold());
        use std::io::{self, Write};
        io::stdout().flush()?;
        
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();
        
        if response != "y" && response != "yes" {
            println!("{}", "Execution aborted by user.".red());
            return Ok(());
        }
    }
    
    println!("\n{}", "=".repeat(70).green().bold());
    println!("{}", "  EXECUTION STARTED".green().bold());
    println!("{}", "=".repeat(70).green().bold());
    
    // Collect all discovered targets (domains/IPs) from various modules
    let mut discovered_targets: Vec<target::Target> = Vec::new();

    // Run zone transfer if selected and we have domains
    if config.run_zone_transfer && !domain_names.is_empty() {
        match zone_transfer::run_zone_transfers(&domain_names, &config.output_dir, config.verbose).await {
            Ok(discovered) => {
                if !discovered.is_empty() {
                    println!("Adding {} discovered hosts from zone transfer to scan targets...", discovered.len());
                    for host in &discovered {
                        // Try to parse as IP first
                        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                            discovered_targets.push(target::Target::IP(ip));
                        } else {
                            // Otherwise treat as domain
                            discovered_targets.push(target::Target::Domain(host.clone()));
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!("Zone transfer error: {}", e);
            }
        }
    }
    
    // Run email verification if selected and we have domains
    if config.run_email_verification && !domain_names.is_empty() {
        if let Err(e) = email_verification::run_email_verification(&domain_names, &config.output_dir, config.verbose).await {
            eprintln!("Email verification error: {}", e);
        }
    }

    // Run crt.sh enumeration if selected and we have domains
    if config.run_crt_sh && !domain_names.is_empty() {
        println!("\n{}", "=".repeat(70).blue().bold());
        println!("{}", "  CRT.SH ENUMERATION".blue().bold());
        println!("{}", "=".repeat(70).blue().bold());

        for domain in &domain_names {
            match crt_sh::fetch_subdomains(domain).await {
                Ok(subdomains) => {
                    if !subdomains.is_empty() {
                        println!("Found {} subdomains for {}:", subdomains.len(), domain);
                        for sub in &subdomains {
                            println!("{}", sub);
                            discovered_targets.push(target::Target::Domain(sub.clone()));
                        }
                    } else {
                        println!("No subdomains found for {} on crt.sh", domain);
                    }
                },
                Err(e) => eprintln!("Error querying crt.sh for {}: {}", domain, e),
            }
        }
    }
    
    // Run actual fuzzing if selected, wordlist provided
    let mut fuzzed_subdomains = Vec::new();
    if config.run_fuzzing {
        if let Some(wordlist) = &config.wordlist {
            println!("\n{}", "=".repeat(70).blue().bold());
            println!("{}", "  SUBDOMAIN FUZZING".blue().bold());
            println!("{}", "=".repeat(70).blue().bold());
            
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
            match fuzzer::fuzz_subdomains(&targets, wordlist, &config.output_dir, config.verbose, cancel_token.clone()).await {
                Ok(found) => {
                    fuzzed_subdomains = found;
                    if !fuzzed_subdomains.is_empty() {
                        println!("Found {} valid subdomains:", fuzzed_subdomains.len());
                        for d in &fuzzed_subdomains {
                            println!("{}", d);
                        }
                        
                        // Add to discovered targets
                        println!("Adding found subdomains to scan targets...");
                        for sub in &fuzzed_subdomains {
                            discovered_targets.push(target::Target::Domain(sub.clone()));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Fuzzing error: {}", e);
                }
            }
        }
    }
    
    // Resolve and merge discovered targets into scan_targets
    // This ensures they are resolved to IPs, checked against strict scope (if enabled), and deduplicated
    if !discovered_targets.is_empty() {
        println!("\nResolving and merging {} discovered targets...", discovered_targets.len());
        
        // We pass the current scan_targets as explicit_ips to resolve_targets
        // This is a bit tricky: resolve_targets uses explicit_ips for TWO things:
        // 1. Initializing the result vector (we don't want this, we want to append)
        // 2. Checking strict scope (we DO want this)
        
        // So we need to be careful.
        // If strict_scope is true, we want to check against the ORIGINAL explicit_ips.
        // If strict_scope is false, we just want to resolve and add.
        
        // But wait, scan_targets currently contains the resolved IPs from the initial targets.
        // If strict_scope is on, we should only allow IPs that match the ORIGINAL explicit_ips.
        // We have `explicit_ips` variable available from earlier in the function?
        // No, `explicit_ips` was a local variable in the block above.
        // We need to reconstruct it or pass it down.
        
        // Actually, `scan_targets` was initialized with `explicit_ips` from the start of `run_scan`.
        // Let's look at the start of `run_scan`:
        // let explicit_ips: Vec<target::Target> = targets...
        // let (mut scan_targets, domain_names) = target::resolve_targets(&targets, &explicit_ips, ...).await?;
        
        // So `explicit_ips` is available here!
        
        let (resolved_discovered, _) = target::resolve_targets(
            &discovered_targets, 
            &explicit_ips, 
            config.verbose, 
            config.strict_scope
        ).await?;
        
        // Now merge resolved_discovered into scan_targets, avoiding duplicates
        for target in resolved_discovered {
            let is_present = scan_targets.iter().any(|t| t == &target);
            if !is_present {
                if config.verbose {
                    println!("Adding new discovered target: {:?}", target);
                }
                scan_targets.push(target);
            }
        }
    }
    
    // Pass scan targets (filtered IPs only) to scanner for actual execution
    let ssl_info = if config.run_port_scan {
        scanner::run_scans(
            &scan_targets, 
            &config.output_dir, 
            false, 
            config.verbose, 
            config.all_formats, 
            config.yes_all,
            config.custom_nmap_args.as_deref(),
            config.firewall_evasion
        ).await?
    } else {
        Vec::new()
    };
    
    // Run testssl.sh if enabled
    if config.run_testssl {
        // Collect domain targets from original input
        let mut domain_targets: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                target::Target::Domain(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
            
        // If we are running ONLY testssl (implied by not running port scan? No, explicit flag),
        // we might want to include IPs.
        // The original logic was: if testssl_only, include IPs.
        // Here, if run_testssl is true, we should probably include IPs if strict_scope is false OR if we want to mimic testssl_only behavior.
        // But wait, testssl.sh works on domains mostly.
        // Let's stick to: if run_testssl is true, we scan domains.
        // If the user provided IPs and wants testssl on them, they should be in domain_targets?
        // The original code added IPs to domain_targets ONLY if testssl_only was true.
        
        // Let's check if we are in a "testssl only" mode effectively
        let is_testssl_only_mode = config.run_testssl && !config.run_port_scan && !config.run_fuzzing && !config.run_zone_transfer && !config.run_email_verification;

        if is_testssl_only_mode {
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
        omniscan::ssl_scanner::run_testssl_scans(&domain_targets, &ssl_info, &config.output_dir, config.verbose).await?;
    }
    
    Ok(())
}
