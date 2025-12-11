use anyhow::Result;
use dialoguer::{theme::ColorfulTheme, Input, Select, Confirm};
use crate::config::ScanConfig;
use colored::*;

pub fn run_interactive_menu() -> Result<ScanConfig> {
    println!("{}", "=".repeat(70).cyan().bold());
    println!("{}", "  OMNISCAN INTERACTIVE MODE".cyan().bold());
    println!("{}", "=".repeat(70).cyan().bold());

    let mut config = ScanConfig::default();

    // 1. Get Targets
    let targets_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter targets (IPs, domains, CIDRs, or file paths) separated by commas or spaces")
        .interact_text()?;

    let raw_targets: Vec<String> = targets_input
        .split(|c| c == ',' || c == ' ')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    for t in raw_targets {
        // Check if it's a file
        if std::path::Path::new(&t).exists() && std::fs::metadata(&t).map(|m| m.is_file()).unwrap_or(false) {
            println!("Reading targets from file: {}", t);
            match crate::utils::read_lines(&t) {
                Ok(lines) => config.targets.extend(lines),
                Err(e) => eprintln!("Failed to read file {}: {}", t, e),
            }
        } else {
            // Assume it's a direct target (IP, Domain, CIDR)
            config.targets.push(t);
        }
    }

    if config.targets.is_empty() {
        println!("{}", "No valid targets provided.".red());
        // Optionally loop back or exit, but for now let's just warn
    } else {
        println!("Loaded {} unique targets.", config.targets.len());
    }

    // 2. Select Modules (Custom Loop for Enter-to-select behavior)
    let mut module_states = vec![
        false, // Port Scanning
        false, // Subdomain Enumeration
        false, // DNS Zone Transfer
        false, // Email Security
        false, // SSL/TLS Scanning
    ];
    
    let module_names = vec![
        "Port Scanning (Nmap)",
        "Subdomain Enumeration (Fuzzing)",
        "DNS Zone Transfer",
        "Email Security (SPF/DMARC/DKIM)",
        "SSL/TLS Scanning (testssl.sh)",
    ];

    let mut selection_index = 0;
    loop {
        // Build menu items with current status
        let mut items: Vec<String> = module_states.iter().zip(module_names.iter())
            .map(|(selected, name)| {
                if *selected {
                    format!("[x] {}", name)
                } else {
                    format!("[ ] {}", name)
                }
            })
            .collect();
        
        // Add Select All / Deselect All option
        let all_selected = module_states.iter().all(|&x| x);
        if all_selected {
            items.push(">> DESELECT ALL <<".bold().yellow().to_string());
        } else {
            items.push(">> SELECT ALL <<".bold().yellow().to_string());
        }

        items.push(">> LAUNCH SCAN <<".bold().green().to_string());

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select modules to toggle (Enter to select, choose Launch to finish)")
            .items(&items)
            .default(selection_index)
            .interact()?;

        selection_index = selection;

        if selection == module_names.len() {
            // Toggle All
            let new_state = !all_selected;
            for state in &mut module_states {
                *state = new_state;
            }
        } else if selection == module_names.len() + 1 {
            // Launch selected
            break;
        } else {
            // Toggle selection
            module_states[selection] = !module_states[selection];
        }
    }

    // Map selections to config
    config.run_port_scan = module_states[0];
    config.run_fuzzing = module_states[1];
    config.run_zone_transfer = module_states[2];
    config.run_email_verification = module_states[3];
    config.run_testssl = module_states[4];

    // 2.1 Port Scan Submenu
    if config.run_port_scan {
        println!("\n{}", "--- Port Scanning Configuration ---".blue());
        let scan_types = vec!["Default Scan", "Custom Scan"];
        let scan_selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose scan type")
            .items(&scan_types)
            .default(0)
            .interact()?;

        if scan_selection == 1 {
            // Custom Scan
            let custom_args: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter custom Nmap arguments (e.g., -sS -T4 -p 80,443)")
                .interact_text()?;
            config.custom_nmap_args = Some(custom_args);
        }

        // Firewall Evasion
        config.firewall_evasion = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable firewall evasion techniques? (Fragment packets, badsum, etc.)")
            .default(false)
            .interact()?;
    }

    // 3. Options
    config.strict_scope = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enforce strict scope? (Only scan resolved IPs that match explicit targets)")
        .default(true)
        .interact()?;

    if config.run_fuzzing {
        let wordlist: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Path to subdomain wordlist")
            .default("wordlist.txt".to_string())
            .interact_text()?;
        config.wordlist = Some(wordlist);
    }

    config.output_dir = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Output directory")
        .default(".".to_string())
        .interact_text()?;

    config.verbose = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable verbose logging?")
        .default(false)
        .interact()?;

    Ok(config)
}
