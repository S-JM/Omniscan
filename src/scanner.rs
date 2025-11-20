use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;
use tokio::signal;
use indicatif::{ProgressBar, ProgressStyle};
use crate::target::Target;

pub async fn run_scans(targets: &[Target], output_dir: &str) -> Result<()> {
    // Convert targets to string list for Nmap
    let target_strings: Vec<String> = targets.iter().map(|t| match t {
        Target::IP(ip) => ip.to_string(),
        Target::Network(net) => net.to_string(),
        Target::Domain(d) => d.clone(),
    }).collect();

    if target_strings.is_empty() {
        println!("No targets to scan.");
        return Ok(());
    }

    // Ensure output directory exists
    if !std::path::Path::new(output_dir).exists() {
        std::fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    }

    // 1. Alive Host Discovery
    println!("\n--- Starting Alive Host Discovery (Ping Scan) ---");
    // Use -oG - to output grepable format to stdout for parsing
    let alive_output = run_nmap_scan("Alive Scan", &["-sn", "-oG", "-"], &target_strings, output_dir, None).await?;
    let alive_hosts = parse_alive_hosts(&alive_output)?;
    
    if alive_hosts.is_empty() {
        println!("No alive hosts found. Exiting.");
        return Ok(());
    }
    println!("Alive hosts: {:?}", alive_hosts);

    // 2. TCP Port Scan (All ports)
    println!("\n--- Starting TCP Port Scan (All Ports) ---");
    // Use -oG - for parsing
    let tcp_output = run_nmap_scan("TCP Scan", &["-p-", "-oG", "-"], &alive_hosts, output_dir, None).await?;

    // 3. UDP Port Scan (Top 1000)
    println!("\n--- Starting UDP Port Scan (Top 1000) ---");
    let udp_output = run_nmap_scan("UDP Scan", &["-sU", "--top-ports", "1000", "-oG", "-"], &alive_hosts, output_dir, None).await?;

    // 4. Service & Script Scan (Default Scripts + Version)
    let tcp_ports = parse_ports_from_gnmap(&tcp_output)?;
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
        println!("\n--- Starting Service & Script Scan ---");
        
        // Construct the full command args manually for this one since we have dynamic ports
        let mut final_args = vec!["-sV", "-sC"];
        // If we have UDP ports, we must add -sU to the final scan to enable UDP scanning
        if !udp_ports.is_empty() {
            final_args.push("-sU");
        }
        // If we have TCP ports (or just to be safe), we usually imply -sS or -sT, but -sU mixed with TCP defaults to -sS for TCP.
        // Nmap handles mixed scans fine if -sU is present.
        
        final_args.push("-p");
        final_args.push(&combined_ports);
        
        // This is the ONLY scan that saves to file
        // Iterate over each host to save output with the IP as the filename
        for host in alive_hosts {
            println!("Scanning host: {}", host);
            let single_target = vec![host.clone()];
            run_nmap_scan("Script Scan", &final_args, &single_target, output_dir, Some(&host)).await?;
        }
    } else {
        println!("Skipping script scan as no ports were found.");
    }

    Ok(())
}

async fn run_nmap_scan(
    name: &str,
    nmap_args: &[&str],
    targets: &[String],
    output_dir: &str,
    output_name: Option<&str>,
) -> Result<String> {
    let mut cmd = Command::new("nmap");
    cmd.args(nmap_args);
    
    if let Some(out_name) = output_name {
        let output_file_base = format!("{}/{}", output_dir, out_name);
        cmd.arg("-oA").arg(&output_file_base);
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
    pb.set_message(format!("Running {}...", name));
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // Wait for child or Ctrl+C
    tokio::select! {
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
    }
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

fn parse_ports_from_gnmap(content: &str) -> Result<Vec<String>> {
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
