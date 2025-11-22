/// SSL/TLS scanner using testssl.sh
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use indicatif::{ProgressBar, ProgressStyle};
use crate::assets;

/// Run testssl.sh against a target (domain or IP)
/// 
/// # Arguments
/// * `target` - The target domain or IP address
/// * `port` - Optional port (defaults to 443)
/// * `output_dir` - Directory to save JSON results
/// * `testssl_path` - Path to the extracted testssl.sh script
/// * `openssl_path` - Path to the extracted openssl binary
pub async fn run_testssl(
    target: &str,
    port: Option<u16>,
    output_dir: &str,
    testssl_path: &Path,
    openssl_path: &Path,
) -> Result<()> {
    let port_str = port.unwrap_or(443).to_string();
    let target_port = format!("{}:{}", target, port_str);
    
    // Sanitize target name for filename
    let safe_target = target.replace(":", "_").replace("/", "_");
    let output_file = format!("{}/{}.json", output_dir, safe_target);
    
    let mut cmd = Command::new("bash");
    cmd.arg(testssl_path)
        .arg("--jsonfile-pretty")
        .arg(&output_file);

    // Check if bundled OpenSSL works
    // We set OPENSSL_CONF to /dev/null to avoid loading system OpenSSL config (e.g. /etc/ssl/openssl.cnf)
    // which might be incompatible (e.g. OpenSSL 3.0 config vs bundled 1.1.1 binary).
    let use_bundled_openssl = if cfg!(unix) {
        match std::process::Command::new(openssl_path)
            .arg("version")
            .env("OPENSSL_CONF", "/dev/null")
            .output() 
        {
            Ok(output) if output.status.success() => {
                true
            },
            Ok(output) => {
                eprintln!("Warning: Bundled OpenSSL failed to run (status {}). Using system OpenSSL instead.", output.status);
                // Only print stderr if verbose or if it's not the common config error
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("configuration file routines") {
                    eprintln!("Stderr: {}", stderr);
                }
                false
            },
            Err(e) => {
                eprintln!("Warning: Failed to execute bundled OpenSSL ({}). Using system OpenSSL instead.", e);
                false
            }
        }
    } else {
        // On Windows, we rely on system OpenSSL
        false
    };

    if use_bundled_openssl {
        cmd.arg("--openssl").arg(openssl_path);
        // Also set env var for the actual execution
        cmd.env("OPENSSL_CONF", "/dev/null");
    }

    // If output file exists, delete it to ensure a fresh scan
    if std::path::Path::new(&output_file).exists() {
        println!("Output file {} already exists, deleting...", output_file);
        if let Err(e) = std::fs::remove_file(&output_file) {
            eprintln!("Warning: Failed to delete existing output file {}: {}", output_file, e);
        }
    }

    cmd.arg(&target_port)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    println!("Running testssl.sh on {}", target_port);
    println!("Command: {:?}", cmd);
    
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message(format!("Testing SSL/TLS on {}...", target));
    
    let output = cmd.output().await.context("Failed to execute testssl.sh")?;
    
    pb.finish_with_message(format!("Completed SSL/TLS scan on {}", target));
    
    if output.status.success() {
        println!("✓ Results saved to: {}", output_file);
    } else {
        eprintln!("testssl.sh failed with status: {}", output.status);
        eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    Ok(())
}

/// Extract SSL/TLS ports from Nmap scan results (service names)
/// This is a simple heuristic based on common SSL port numbers
pub fn is_ssl_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 8888 | 9443 | 10443 | 8843) || port == 636 || port == 993 || port == 995 || port == 465
}

/// Run testssl.sh on all relevant targets
pub async fn run_testssl_scans(
    domains: &[String],
    ip_ssl_ports: &[(String, u16)],
    output_dir: &str,
) -> Result<()> {
    println!("\n{}", "=".repeat(70));
    println!("  SSL/TLS SECURITY SCAN (testssl.sh)");
    println!("{}", "=".repeat(70));
    
    // Extract assets - now returns (temp_dir, testssl_dir, script_path, openssl_path)
    let (temp_dir, _testssl_dir, testssl_path, openssl_path) = assets::extract_assets()
        .context("Failed to extract testssl.sh assets")?;
    
    println!("Extracted testssl.sh to: {:?}", testssl_path);
    println!("Extracted openssl to: {:?}", openssl_path);
    println!("{}", "-".repeat(70));
    
    // Scan domains
    if !domains.is_empty() {
        println!("\nScanning {} domain(s):", domains.len());
        for domain in domains {
            if let Err(e) = run_testssl(domain, None, output_dir, &testssl_path, &openssl_path).await {
                eprintln!("Failed to scan {}: {}", domain, e);
            }
        }
    }
    
    // Scan IPs with SSL ports
    if !ip_ssl_ports.is_empty() {
        println!("\nScanning {} IP:port pair(s) with SSL/TLS:", ip_ssl_ports.len());
        for (ip, port) in ip_ssl_ports {
            if let Err(e) = run_testssl(ip, Some(*port), output_dir, &testssl_path, &openssl_path).await {
                eprintln!("Failed to scan {}:{}: {}", ip, port, e);
            }
        }
    }
    
    // Keep temp_dir alive until scans complete
    drop(temp_dir);
    
    println!("{}", "=".repeat(70));
    println!("  SSL/TLS SCAN COMPLETE");
    println!("{}", "=".repeat(70));
    
    Ok(())
}
