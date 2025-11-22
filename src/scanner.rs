use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tokio::signal;
use indicatif::{ProgressBar, ProgressStyle};
use crate::target::Target;
use colored::*;

/// Orchestrates the Nmap scanning process.
///
/// This function performs a sequence of scans:
/// 1. Alive Host Discovery (Ping Scan)
/// 2. TCP Port Scan (All Ports)
/// 3. UDP Port Scan (Top 1000 Ports)
/// 4. Service & Script Scan (on discovered ports)
///
/// Only the final scan saves output to files.
///
/// Returns a vector of (IP, port) tuples representing discovered SSL/TLS services.
pub async fn run_scans(targets: &[Target], output_dir: &str, dry_run: bool, verbose: bool, all_formats: bool, _testssl: bool, yes_all: bool) -> Result<Vec<(String, u16)>> {
    if verbose {
        eprintln!("[VERBOSE] Starting scan orchestration, dry_run={}", dry_run);
        eprintln!("[VERBOSE] Output format: {}", if all_formats { "all formats (-oA)" } else { "XML only (-oX)" });
    }

    // Convert targets to string list for Nmap
    let target_strings: Vec<String> = targets.iter().map(|t| match t {
        Target::IP(ip) => ip.to_string(),
        Target::Network(net) => net.to_string(),
        Target::Domain(d) => d.clone(),
    }).collect();

    if target_strings.is_empty() {
        println!("No targets to scan.");
        return Ok(Vec::new());
    }

    // If dry-run mode, build and print all commands without executing
    if dry_run {
        // 1. Alive Host Discovery
        let alive_cmd = build_command("nmap", &["-sn", "-PS21,22,23,25,80,113,443,3389", "-PA80,443", "-PE", "-PP", "-PU53,123,161", "-oG", "-"], &target_strings, output_dir, None);
        println!("# Alive Host Discovery (Multiple Techniques)");
        println!("# Using ICMP (echo, timestamp), TCP SYN/ACK, UDP ping");
        println!("{}\n", alive_cmd);
        
        // 2. TCP Port Scan
        let tcp_cmd = build_command("nmap", &["-p-", "-oG", "-"], &target_strings, output_dir, None);
        println!("# TCP Port Scan (All Ports)");
        println!("{}\n", tcp_cmd);
        
        // 3. UDP Port Scan
        let udp_cmd = build_command("nmap", &["-sU", "--top-ports", "1000", "-oG", "-"], &target_strings, output_dir, None);
        println!("# UDP Port Scan (Top 1000)");
        println!("{}\n", udp_cmd);
        
        // 4. Service & Script Scan (example with placeholder ports)
        println!("# Service & Script Scan (will run for each alive host with discovered ports)");
        println!("# Example for a single host with mixed TCP and UDP ports:");
        let script_cmd = build_command("nmap", &["-sV", "-sC", "-sS", "-sU", "-p", "T:80,443,U:53,123"], &["<HOST>"], output_dir, Some("<HOST>"));
        println!("{}\n", script_cmd);
        
        return Ok(Vec::new());
    }

    // Ensure output directory exists
    if !std::path::Path::new(output_dir).exists() {
        std::fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    }

    // 1. Alive Host Discovery
    if verbose {
        eprintln!("[VERBOSE] Starting alive host discovery on {} targets", target_strings.len());
        eprintln!("[VERBOSE] Using multiple techniques: ICMP echo/timestamp, TCP SYN/ACK, UDP ping");
    }
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  ALIVE HOST DISCOVERY".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Techniques: ICMP (echo, timestamp), TCP SYN/ACK, UDP ping");
    println!("Ports: TCP 21,22,23,25,80,113,443,3389 | UDP 53,123,161");
    println!("{}", "-".repeat(70));
    
    // Use multiple techniques to detect hosts that might be blocking ICMP or behind firewalls:
    // -sn: No port scan (just host discovery)
    // -PS: TCP SYN ping to common ports (FTP, SSH, Telnet, SMTP, HTTP, Auth, HTTPS, RDP)
    // -PA: TCP ACK ping to web ports (HTTP, HTTPS)
    // -PE: ICMP echo request (traditional ping)
    // -PP: ICMP timestamp request
    // -PU: UDP ping to common ports (DNS, NTP, SNMP)
    // -oG -: Output in grepable format to stdout for parsing
    let alive_output = run_nmap_scan(
        "Alive Scan", 
        &["-sn", "-PS21,22,23,25,80,113,443,3389", "-PA80,443", "-PE", "-PP", "-PU53,123,161", "-oG", "-"], 
        &target_strings, 
        output_dir, 
        None,
        all_formats
    ).await?;
    let alive_hosts = parse_alive_hosts(&alive_output)?;
    
    let mut scan_targets = alive_hosts;
    let mut use_pn = false;
    
    if scan_targets.is_empty() {
        println!("{}", "No alive hosts found.".red());
        
        // Ask user if they want to continue with -Pn (skip host discovery), or auto-continue if yes_all
        if yes_all {
            println!("No hosts responded to ping. Continuing with -Pn (--yes-all)...");
            scan_targets = target_strings.clone();
            use_pn = true;
        } else {
            use std::io::{self, Write};
            print!("No hosts responded to ping. Continue scanning with -Pn (treat all hosts as online)? [y/N]: ");
            io::stdout().flush()?;
            
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            let response = response.trim().to_lowercase();
            
            if response == "y" || response == "yes" {
                println!("Continuing with -Pn flag...");
                scan_targets = target_strings.clone();
                use_pn = true;
            } else {
                println!("{}", "Exiting.".red());
                return Ok(Vec::new());
            }
        }
    } else {
        println!("{}", "-".repeat(70));
        println!("{} {} alive host(s): {:?}", "✓ Found".green(), scan_targets.len(), scan_targets);
        println!("{}", "=".repeat(70));
    }

    // 2. TCP Port Scan (All ports)
    if verbose {
        eprintln!("[VERBOSE] Starting TCP port scan on {} hosts", scan_targets.len());
    }
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  TCP PORT SCAN".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Scanning all 65535 TCP ports on {} host(s)", scan_targets.len());
    println!("{}", "-".repeat(70));
    // Always use -Pn for port scans since we've already done alive host discovery
    // OR if user explicitly requested -Pn mode
    let tcp_args = vec!["-Pn", "-p-", "-oG", "-"];
    let tcp_output = run_nmap_scan("TCP Scan", &tcp_args, &scan_targets, output_dir, None, all_formats).await?;

    // 2.5. Evasion Rescans (for hosts with ≤1 TCP port)
    // Parse ports per host to identify low-port hosts
    let tcp_host_ports = parse_ports_per_host_from_gnmap(&tcp_output)?;
    
    // Perform evasion rescans if any hosts have ≤1 ports
    let evasion_ports = perform_evasion_rescans(&tcp_host_ports, use_pn, output_dir, all_formats, yes_all).await?;
    
    // Merge evasion-discovered ports into tcp_host_ports for final scan
    let mut combined_tcp_host_ports = tcp_host_ports.clone();
    for (host, new_ports) in evasion_ports {
        combined_tcp_host_ports.entry(host).or_insert_with(Vec::new).extend(new_ports);
    }

    // 3. UDP Port Scan (Top 1000)
    if verbose {
        eprintln!("[VERBOSE] Starting UDP port scan on {} hosts", scan_targets.len());
    }
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  UDP PORT SCAN".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Scanning top 1000 UDP ports + high-value ports on {} host(s)", scan_targets.len());
    println!("High-value ports: 67,68,69,514,520,1434,1900,4500,5353");
    println!("{}", "-".repeat(70));
    // Always use -Pn since we've already done alive host discovery
    let udp_args = vec!["-Pn", "-sU", "--top-ports", "1000", "-p", "U:67,68,69,514,520,1434,1900,4500,5353", "-oG", "-"];
    let udp_output = run_nmap_scan("UDP Scan", &udp_args, &scan_targets, output_dir, None, all_formats).await?;

    // 4. Service & Script Scan (Default Scripts + Version)
    // Collect all TCP ports from combined_tcp_host_ports (includes evasion discoveries)
    let mut tcp_ports: Vec<String> = Vec::new();
    for ports in combined_tcp_host_ports.values() {
        for port in ports {
            if !tcp_ports.contains(port) {
                tcp_ports.push(port.clone());
            }
        }
    }
    
    let udp_ports = parse_ports_from_gnmap(&udp_output)?;
    
    let mut combined_ports = String::new();

    if !tcp_ports.is_empty() {
        combined_ports.push_str("T:");
        combined_ports.push_str(&tcp_ports.join(","));
    }
    
    if !udp_ports.is_empty() {
        if !combined_ports.is_empty() {
            combined_ports.push(',');
        }
        combined_ports.push_str("U:");
        combined_ports.push_str(&udp_ports.join(","));
    }

    if !combined_ports.is_empty() {
        println!("\n{}", "=".repeat(70).blue().bold());
        println!("{}", "  SERVICE & SCRIPT SCAN".blue().bold());
        println!("{}", "=".repeat(70).blue().bold());
        println!("Running version detection, OS detection, and default scripts on discovered ports");
        println!("{}", "-".repeat(70));
        
        // Construct the full command args manually for this one since we have dynamic ports
        let mut final_args = vec!["-sV", "-sC", "-O", "-Pn"];
        
        // If we have UDP ports, we must add -sU to the final scan to enable UDP scanning
        if !udp_ports.is_empty() {
            final_args.push("-sU");
        }
        
        // If we have TCP ports, we must specify a TCP scan type (like -sS) if -sU is also present,
        // otherwise Nmap complains "Your ports include 'T:' but you haven't specified any TCP scan type".
        if !tcp_ports.is_empty() {
            final_args.push("-sS");
        }
        
        final_args.push("-p");
        final_args.push(&combined_ports);
        
        // This is the ONLY scan that saves to file
        // Iterate over each host to save output with the IP as the filename
        for host in scan_targets {
            println!("Scanning host: {}", host);
            let single_target = vec![host.clone()];
            run_nmap_scan("Script Scan", &final_args, &single_target, output_dir, Some(&host), all_formats).await?;
        }
    } else {
        println!("\n{}", "=".repeat(70).yellow());
        println!("{}", "  SERVICE & SCRIPT SCAN - SKIPPED".yellow().bold());
        println!("{}", "=".repeat(70).yellow());
        println!("No open ports were found, skipping service detection.");
    }

    println!("\n{}", "=".repeat(70).green().bold());
    println!("{}", "  SCAN COMPLETE".green().bold());
    println!("{}", "=".repeat(70).green().bold());
    
    // Return empty vec for now - SSL port detection will be done in main.rs
    Ok(Vec::new())
}

/// Perform evasion rescans on hosts with 1 or fewer TCP ports
/// Interactive prompts for each technique: fragmented, source port 53/88, badsum, data-length
async fn perform_evasion_rescans(
    host_ports: &std::collections::HashMap<String, Vec<String>>,
    use_pn: bool,
    output_dir: &str,
    all_formats: bool,
    yes_all: bool,
) -> Result<std::collections::HashMap<String, Vec<String>>> {
    use std::collections::HashMap;
    use std::io::{self, Write};
    
    let mut additional_ports: HashMap<String, Vec<String>> = HashMap::new();
    
    // Evasion techniques to try
    let techniques = vec![
        ("Fragmented packets", vec!["-f"]),
        ("Source port 53 (DNS)", vec!["--source-port", "53"]),
        ("Source port 88 (Kerberos)", vec!["--source-port", "88"]),
        ("Bad checksum", vec!["--badsum"]),
        ("Data length padding", vec!["--data-length", "25"]),
    ];
    
    // Find hosts with 1 or fewer TCP ports
    let low_port_hosts: Vec<_> = host_ports
        .iter()
        .filter(|(_, ports)| ports.len() <= 1)
        .map(|(host, _)| host.clone())
        .collect();
    
    if low_port_hosts.is_empty() {
        return Ok(additional_ports);
    }
    
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  FIREWALL EVASION RESCANS".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Found {} host(s) with ≤1 TCP port", low_port_hosts.len());
    println!("Hosts: {:?}", low_port_hosts);
    println!("{}", "-".repeat(70));
    
    let mut yes_to_all = yes_all;

    for host in &low_port_hosts {
        let current_ports = host_ports.get(host).map(|p| p.len()).unwrap_or(0);
        println!("\n[Host: {} ({} open ports)]", host, current_ports);
        
        let mut skip_all = false;
        
        for (name, flags) in &techniques {
            if skip_all {
                break;
            }
            
            if !yes_to_all {
                print!("Try evasion technique: {}? [y/n/all/skip all]: ", name);
                io::stdout().flush()?;
                
                let mut response = String::new();
                io::stdin().read_line(&mut response)?;
                let response = response.trim().to_lowercase();
                
                if response == "skip all" || response == "a" {
                    skip_all = true;
                    println!("Skipping all remaining evasion techniques for all hosts.");
                    break;
                }
                
                if response == "all" || response == "yes to all" {
                    yes_to_all = true;
                    println!("Enabling all remaining evasion techniques for all hosts.");
                } else if response != "y" && response != "yes" {
                    println!("Skipping {}.", name);
                    continue;
                }
            }
            
            // Build scan args with evasion flag
            let mut scan_args = flags.clone();
            if use_pn {
                scan_args.insert(0, "-Pn");
            }
            scan_args.extend_from_slice(&["-p-", "-oG", "-"]);
            
            println!("{}", "-".repeat(70));
            println!("Scanning host {} with evasion technique: {}", host, name);
            println!("{}", "-".repeat(70));
            let output = run_nmap_scan(
                &format!("Evasion Scan ({})", name),
                &scan_args.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
                &vec![host.clone()],
                output_dir,
                None,
                all_formats,
            ).await?;
            
            // Parse discovered ports
            let host_port_map = parse_ports_per_host_from_gnmap(&output)?;
            if let Some(new_ports) = host_port_map.get(host) {
                if !new_ports.is_empty() {
                    println!("{} {} new port(s) with {}: {:?}", "✓ Found".green(), new_ports.len(), name, new_ports);
                    additional_ports.insert(host.clone(), new_ports.clone());
                    break; // Found ports, move to next host
                } else {
                    println!("No new ports found with {}.", name);
                }
            }
        }
        
        if skip_all {
            break;
        }
    }
    
    Ok(additional_ports)
}

async fn run_nmap_scan(
    name: &str,
    nmap_args: &[&str],
    targets: &[String],
    output_dir: &str,
    output_name: Option<&str>,
    all_formats: bool,
) -> Result<String> {
    let mut cmd = Command::new("nmap");
    cmd.args(nmap_args);
    
    if let Some(out_name) = output_name {
        let output_file_base = format!("{}/{}", output_dir, out_name);
        if all_formats {
            // Output all formats: XML, normal text, and grepable
            cmd.arg("-oA").arg(&output_file_base);
        } else {
            // Output XML only (default)
            let xml_file = format!("{}.xml", output_file_base);
            cmd.arg("-oX").arg(&xml_file);
        }
    }

    cmd.args(targets)
       .stdout(Stdio::piped())
       .stderr(Stdio::piped())
       .kill_on_drop(true);

    println!("Running: {:?}", cmd);

    let child = cmd.spawn().context("Failed to spawn nmap")?;
    
    // Progress bar (spinner)
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // Spawn a task to update elapsed time periodically
    let pb_clone = pb.clone();
    let name_clone = name.to_string();
    let start_time = std::time::Instant::now();
    let progress_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.tick().await; // Skip first immediate tick
        loop {
            interval.tick().await;
            let elapsed = start_time.elapsed().as_secs();
            pb_clone.set_message(format!("Running {} ({}s elapsed)...", name_clone, elapsed));
        }
    });

    pb.set_message(format!("Running {} (0s elapsed)...", name));

    // Wait for child or Ctrl+C
    let result = tokio::select! {
        output_result = child.wait_with_output() => {
            pb.finish_with_message(format!("{} finished.", name));
            match output_result {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    Ok(stdout)
                }
                Ok(output) => {
                    eprintln!("Nmap failed with status: {}", output.status);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("Stderr: {}", stderr);
                    Ok(String::new())
                }
                Err(e) => {
                    eprintln!("Failed to wait for nmap: {}", e);
                    Ok(String::new())
                }
            }
        }
        _ = signal::ctrl_c() => {
            pb.finish_with_message(format!("{} skipped by user.", name));
            // Child is dropped here, and kill_on_drop(true) ensures it's killed.
            println!("\nSkipping {}...", name);
            Ok(String::new())
        }
    };

    // Stop the progress update task
    progress_task.abort();

    result
}

fn parse_alive_hosts(content: &str) -> Result<Vec<String>> {
    let mut alive = Vec::new();
    for line in content.lines() {
        if line.contains("Status: Up") {
            // Format: Host: 192.168.1.1 ()	Status: Up
            if let Some(host_part) = line.split("Host: ").nth(1) {
                if let Some(ip) = host_part.split_whitespace().next() {
                    alive.push(ip.to_string());
                }
            }
        }
    }
    Ok(alive)
}

pub fn parse_ports_from_gnmap(content: &str) -> Result<Vec<String>> {
    // Format: Host: 192.168.1.1 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    let mut ports = Vec::new();
    for line in content.lines() {
        if let Some(ports_part) = line.split("Ports: ").nth(1) {
            for port_entry in ports_part.split(", ") {
                if port_entry.contains("/open/") {
                    if let Some(port) = port_entry.split('/').next() {
                        if !ports.contains(&port.to_string()) {
                            ports.push(port.to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(ports)
}

/// Parse open TCP ports per host from grepable nmap output
/// Returns a HashMap mapping each host IP to its list of open ports
pub fn parse_ports_per_host_from_gnmap(content: &str) -> Result<std::collections::HashMap<String, Vec<String>>> {
    use std::collections::HashMap;
    let mut host_ports: HashMap<String, Vec<String>> = HashMap::new();
    
    for line in content.lines() {
        // Extract host IP
        if let Some(host_part) = line.split("Host: ").nth(1) {
            if let Some(ip) = host_part.split_whitespace().next() {
                let host_ip = ip.to_string();
                
                // Extract ports if present
                if let Some(ports_part) = line.split("Ports: ").nth(1) {
                    let mut ports = Vec::new();
                    for port_entry in ports_part.split(", ") {
                        if port_entry.contains("/open/") {
                            if let Some(port) = port_entry.split('/').next() {
                                ports.push(port.to_string());
                            }
                        }
                    }
                    host_ports.insert(host_ip, ports);
                } else {
                    // Host exists but no ports section (0 ports)
                    host_ports.entry(host_ip).or_insert_with(Vec::new);
                }
            }
        }
    }
    Ok(host_ports)
}

fn build_command(
    program: &str,
    nmap_args: &[&str],
    targets: &[impl AsRef<str>],
    output_dir: &str,
    output_name: Option<&str>,
) -> String {
    let mut cmd_parts = vec![program.to_string()];
    
    // Add nmap args
    for arg in nmap_args {
        cmd_parts.push(arg.to_string());
    }
    
    // Add output file args if specified
    if let Some(out_name) = output_name {
        let output_file_base = format!("{}/{}", output_dir, out_name);
        cmd_parts.push("-oA".to_string());
        cmd_parts.push(output_file_base);
    }
    
    // Add targets
    for target in targets {
        cmd_parts.push(target.as_ref().to_string());
    }
    
    cmd_parts.join(" ")
}
