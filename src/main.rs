use clap::Parser;
use anyhow::Result;
use nmap_helper::target::{self, Target};
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

    // Subdomain Fuzzing
    if let Some(wordlist) = args.wordlist {
        println!("\n--- Starting Subdomain Fuzzing ---");
        let found_subdomains = fuzzer::fuzz_subdomains(&targets, &wordlist).await?;
        if !found_subdomains.is_empty() {
            println!("Found {} valid subdomains:", found_subdomains.len());
            for d in &found_subdomains {
                println!("{}", d);
                // Add found subdomains to targets for scanning
                // Note: We need to resolve them to IPs for Nmap or just pass the domain?
                // Nmap handles domains, but we want to scan the specific IP that matched?
                // For now, let's just add the domain string to the list of things to scan.
                // However, our `targets` vector is `Vec<Target>`.
                // We should probably add them as Target::Domain.
            }
        }
        
        // TODO: Add found subdomains to a list for scanning
    } else {
        // Check if there are domains but no wordlist
        let has_domains = targets.iter().any(|t| matches!(t, target::Target::Domain(_)));
        if has_domains {
             println!("\n[WARN] Domain targets detected but no wordlist provided. Skipping subdomain fuzzing.");
        }
    }

    // Pass targets to scanner
    scanner::run_scans(&targets, &args.output_dir, args.dry_run).await?;
    
    Ok(())
}
