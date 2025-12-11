/// SSL/TLS scanner using testssl.sh
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use indicatif::{ProgressBar, ProgressStyle};
use crate::assets;
use colored::*;

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
    verbose: bool,
) -> Result<()> {
    let port_str = port.unwrap_or(443).to_string();
    let target_port = format!("{}:{}", target, port_str);
    
    // Sanitize target name for filename
    let safe_target = crate::utils::sanitize_for_filename(target);
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
                println!("{} {}", "✓ Bundled OpenSSL is functional:".green(), String::from_utf8_lossy(&output.stdout).trim());
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
    if verbose {
        println!("Command: {:?}", cmd);
    }
    
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}")?);
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message(format!("Testing SSL/TLS on {}...", target));
    
    let output = cmd.output().await.context("Failed to execute testssl.sh")?;
    
    pb.finish_with_message(format!("Completed SSL/TLS scan on {}", target));
    
    if output.status.success() {
        println!("{} {}", "✓ Results saved to:".green(), output_file);
    } else {
        eprintln!("{} {}", "testssl.sh failed with status:".red(), output.status);
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
    verbose: bool,
) -> Result<()> {
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  SSL/TLS SECURITY SCAN (testssl.sh)".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    
    // Extract assets - now returns (temp_dir, testssl_dir, script_path, openssl_path)
    let (temp_dir, _testssl_dir, testssl_path, openssl_path) = assets::extract_assets()
        .context("Failed to extract testssl.sh assets")?;
    
    if verbose {
        println!("Extracted testssl.sh to: {:?}", testssl_path);
        println!("Extracted openssl to: {:?}", openssl_path);
    }
    println!("{}", "-".repeat(70));
    
    // Scan domains
    if !domains.is_empty() {
        println!("\nScanning {} domain(s):", domains.len());
        for domain in domains {
            // Allow skipping individual targets with Ctrl+C
            let result = tokio::select! {
                res = run_testssl(domain, None, output_dir, &testssl_path, &openssl_path, verbose) => res,
                _ = tokio::signal::ctrl_c() => {
                    println!("\n{} {}", "Skipping SSL scan for".yellow(), domain);
                    continue;
                }
            };

            if let Err(e) = result {
                eprintln!("{} {}: {}", "Failed to scan".red(), domain, e);
            }
        }
    }
    
    // Scan IPs with SSL ports
    if !ip_ssl_ports.is_empty() {
        println!("\nScanning {} IP:port pair(s) with SSL/TLS:", ip_ssl_ports.len());
        for (ip, port) in ip_ssl_ports {
            let target_display = format!("{}:{}", ip, port);
            
            // Allow skipping individual targets with Ctrl+C
            let result = tokio::select! {
                res = run_testssl(ip, Some(*port), output_dir, &testssl_path, &openssl_path, verbose) => res,
                _ = tokio::signal::ctrl_c() => {
                    println!("\n{} {}", "Skipping SSL scan for".yellow(), target_display);
                    continue;
                }
            };

            if let Err(e) = result {
                eprintln!("{} {}: {}", "Failed to scan".red(), target_display, e);
            }
        }
    }
    
    // Keep temp_dir alive until scans complete
    drop(temp_dir);
    
    println!("{}", "=".repeat(70).green().bold());
    println!("{}", "  SSL/TLS SCAN COMPLETE".green().bold());
    println!("{}", "=".repeat(70).green().bold());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ssl_port_https() {
        assert!(is_ssl_port(443));
    }

    #[test]
    fn test_is_ssl_port_alternate_https() {
        assert!(is_ssl_port(8443));
        assert!(is_ssl_port(9443));
        assert!(is_ssl_port(10443));
    }

    #[test]
    fn test_is_ssl_port_ldaps() {
        assert!(is_ssl_port(636));
    }

    #[test]
    fn test_is_ssl_port_imaps() {
        assert!(is_ssl_port(993));
    }

    #[test]
    fn test_is_ssl_port_pop3s() {
        assert!(is_ssl_port(995));
    }

    #[test]
    fn test_is_ssl_port_smtps() {
        assert!(is_ssl_port(465));
    }

    #[test]
    fn test_is_ssl_port_non_ssl() {
        assert!(!is_ssl_port(80));  // HTTP
        assert!(!is_ssl_port(22));  // SSH
        assert!(!is_ssl_port(21));  // FTP
        assert!(!is_ssl_port(25));  // SMTP
        assert!(!is_ssl_port(3306)); // MySQL
    }

    #[test]
    fn test_is_ssl_port_edge_cases() {
        assert!(!is_ssl_port(0));
        assert!(!is_ssl_port(1));
        assert!(!is_ssl_port(65535));
    }
}
