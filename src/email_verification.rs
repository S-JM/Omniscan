/// Email DNS verification module for SPF, DMARC, and DKIM records
use anyhow::{Context, Result};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use colored::*;

/// Email verification findings
#[derive(Debug, Clone)]
pub struct EmailVerificationResult {
    pub domain: String,
    pub spf_present: bool,
    pub spf_record: Option<String>,
    pub spf_issues: Vec<String>,
    pub dmarc_present: bool,
    pub dmarc_record: Option<String>,
    pub dmarc_issues: Vec<String>,
    pub dkim_selectors_found: Vec<String>,
    pub dkim_issues: Vec<String>,
    pub mx_records: Vec<String>,
    pub mx_issues: Vec<String>,
    pub smtp_checks: Vec<SmtpCheckResult>,
    pub blacklist_results: Vec<BlacklistResult>,
}

/// SMTP check result for an MX server
#[derive(Debug, Clone)]
pub struct SmtpCheckResult {
    pub mx_host: String,
    pub mx_ip: String,
    pub reverse_dns: Option<String>,
    pub reverse_dns_valid: bool,
    pub smtp_banner: Option<String>,
    pub banner_matches_rdns: bool,
    pub supports_tls: bool,
    pub is_open_relay: bool,
    pub issues: Vec<String>,
}

/// Blacklist check result
#[derive(Debug, Clone)]
pub struct BlacklistResult {
    pub ip: String,
    pub blacklist_name: String,
    pub is_listed: bool,
}

/// Common DKIM selectors to check
const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
    "mail",
    "smtp",
];

/// Verify email DNS records for a domain
pub async fn verify_email_dns(
    domain: &str,
    verbose: bool,
) -> Result<EmailVerificationResult> {
    if verbose {
        eprintln!("[VERBOSE] Starting email DNS verification for: {}", domain);
    }
    
    println!("{} {}", "Verifying email DNS records for:".blue(), domain);
    
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default());
    
    let mut result = EmailVerificationResult {
        domain: domain.to_string(),
        spf_present: false,
        spf_record: None,
        spf_issues: Vec::new(),
        dmarc_present: false,
        dmarc_record: None,
        dmarc_issues: Vec::new(),
        dkim_selectors_found: Vec::new(),
        dkim_issues: Vec::new(),
        mx_records: Vec::new(),
        mx_issues: Vec::new(),
        smtp_checks: Vec::new(),
        blacklist_results: Vec::new(),
    };
    
    // Check MX records
    println!("  {} MX records...", "Checking".blue());
    check_mx(&resolver, domain, &mut result, verbose).await?;
    
    // Check SPF
    println!("  {} SPF record...", "Checking".blue());
    check_spf(&resolver, domain, &mut result, verbose).await?;
    
    // Check DMARC
    println!("  {} DMARC record...", "Checking".blue());
    check_dmarc(&resolver, domain, &mut result, verbose).await?;
    
    // Check DKIM
    println!("  {} DKIM records...", "Checking".blue());
    check_dkim(&resolver, domain, &mut result, verbose).await?;
    
    // Check domain blacklists (RHSBL)
    println!("  {} Domain blacklists...", "Checking".blue());
    check_domain_blacklists(&resolver, domain, &mut result, verbose).await?;
    
    Ok(result)
}

/// Check SPF record
async fn check_spf(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    match resolver.txt_lookup(domain).await {
        Ok(lookup) => {
            for record in lookup.iter() {
                let txt_data = record.iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                    .collect::<Vec<_>>()
                    .join("");
                
                if txt_data.starts_with("v=spf1") {
                    result.spf_present = true;
                    result.spf_record = Some(txt_data.clone());
                    
                    if verbose {
                        eprintln!("[VERBOSE] Found SPF record: {}", txt_data);
                    }
                    
                    println!("    {} SPF record found", "✓".green());
                    
                    // Validate SPF record
                    validate_spf(&txt_data, result);
                    break;
                }
            }
            
            if !result.spf_present {
                println!("    {} No SPF record found", "✗".red());
                result.spf_issues.push("SPF record not found".to_string());
            }
        },
        Err(e) => {
            if verbose {
                eprintln!("[VERBOSE] SPF lookup failed: {}", e);
            }
            println!("    {} No SPF record found", "✗".red());
            result.spf_issues.push("SPF record not found".to_string());
        }
    }
    
    Ok(())
}

/// Validate SPF record for common issues
fn validate_spf(spf: &str, result: &mut EmailVerificationResult) {
    // Check for all mechanism
    if spf.contains("+all") {
        result.spf_issues.push("CRITICAL: SPF uses '+all' (allows all senders)".to_string());
        println!("    {} CRITICAL: SPF uses '+all' (allows all senders)", "⚠".red());
    } else if spf.contains("?all") {
        result.spf_issues.push("WARNING: SPF uses '?all' (neutral policy)".to_string());
        println!("    {} WARNING: SPF uses '?all' (neutral policy)", "⚠".yellow());
    } else if !spf.contains("-all") && !spf.contains("~all") {
        result.spf_issues.push("WARNING: SPF missing '-all' or '~all' terminator".to_string());
        println!("    {} WARNING: SPF missing '-all' or '~all' terminator", "⚠".yellow());
    } else if spf.contains("-all") {
        println!("    {} SPF has strict policy (-all)", "✓".green());
    } else if spf.contains("~all") {
        println!("    {} SPF has soft fail policy (~all)", "✓".green());
    }
    
    // Count DNS lookups (include, a, mx, ptr, exists)
    let lookup_count = spf.matches("include:").count() 
        + spf.matches(" a").count()
        + spf.matches(" mx").count()
        + spf.matches("ptr:").count()
        + spf.matches("exists:").count();
    
    if lookup_count > 10 {
        result.spf_issues.push(format!("WARNING: SPF has {} DNS lookups (max 10 recommended)", lookup_count));
        println!("    {} WARNING: SPF has {} DNS lookups (max 10 recommended)", "⚠".yellow(), lookup_count);
    }
}

/// Check DMARC record
async fn check_dmarc(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    let dmarc_domain = format!("_dmarc.{}", domain);
    
    match resolver.txt_lookup(&dmarc_domain).await {
        Ok(lookup) => {
            for record in lookup.iter() {
                let txt_data = record.iter()
                    .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                    .collect::<Vec<_>>()
                    .join("");
                
                if txt_data.starts_with("v=DMARC1") {
                    result.dmarc_present = true;
                    result.dmarc_record = Some(txt_data.clone());
                    
                    if verbose {
                        eprintln!("[VERBOSE] Found DMARC record: {}", txt_data);
                    }
                    
                    println!("    {} DMARC record found", "✓".green());
                    
                    // Validate DMARC record
                    validate_dmarc(&txt_data, result);
                    break;
                }
            }
            
            if !result.dmarc_present {
                println!("    {} No DMARC record found", "✗".red());
                result.dmarc_issues.push("DMARC record not found".to_string());
            }
        },
        Err(e) => {
            if verbose {
                eprintln!("[VERBOSE] DMARC lookup failed: {}", e);
            }
            println!("    {} No DMARC record found", "✗".red());
            result.dmarc_issues.push("DMARC record not found".to_string());
        }
    }
    
    Ok(())
}

/// Validate DMARC record for common issues
fn validate_dmarc(dmarc: &str, result: &mut EmailVerificationResult) {
    // Check policy
    if dmarc.contains("p=none") {
        result.dmarc_issues.push("WARNING: DMARC policy is 'none' (monitoring only)".to_string());
        println!("    {} WARNING: DMARC policy is 'none' (monitoring only)", "⚠".yellow());
    } else if dmarc.contains("p=quarantine") {
        println!("    {} DMARC policy is 'quarantine'", "✓".green());
    } else if dmarc.contains("p=reject") {
        println!("    {} DMARC policy is 'reject' (strict)", "✓".green());
    }
    
    // Check for reporting addresses
    if !dmarc.contains("rua=") && !dmarc.contains("ruf=") {
        result.dmarc_issues.push("WARNING: DMARC has no reporting addresses (rua/ruf)".to_string());
        println!("    {} WARNING: DMARC has no reporting addresses", "⚠".yellow());
    }
    
    // Check subdomain policy
    if !dmarc.contains("sp=") {
        result.dmarc_issues.push("INFO: DMARC has no subdomain policy (sp)".to_string());
    }
}

/// Check DKIM records using common selectors
async fn check_dkim(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    let mut found_any = false;
    
    for selector in COMMON_DKIM_SELECTORS {
        let dkim_domain = format!("{}._domainkey.{}", selector, domain);
        
        if verbose {
            eprintln!("[VERBOSE] Checking DKIM selector: {}", selector);
        }
        
        match resolver.txt_lookup(&dkim_domain).await {
            Ok(lookup) => {
                for record in lookup.iter() {
                    let txt_data = record.iter()
                        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                        .collect::<Vec<_>>()
                        .join("");
                    
                    if txt_data.contains("v=DKIM1") || txt_data.contains("k=rsa") || txt_data.contains("p=") {
                        result.dkim_selectors_found.push(selector.to_string());
                        found_any = true;
                        
                        if verbose {
                            eprintln!("[VERBOSE] Found DKIM record for selector '{}': {}", selector, txt_data);
                        }
                        
                        println!("    {} DKIM selector '{}' found", "✓".green(), selector);
                        break;
                    }
                }
            },
            Err(_) => {
                // Selector not found, continue to next
            }
        }
    }
    
    if !found_any {
        println!("    {} No DKIM records found (checked common selectors)", "✗".yellow());
        result.dkim_issues.push("No DKIM records found for common selectors".to_string());
    }
    
    Ok(())
}

/// Check MX records and perform SMTP verification
async fn check_mx(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    
    match resolver.mx_lookup(domain).await {
        Ok(lookup) => {
            let mut mx_hosts: Vec<(u16, String)> = lookup.iter()
                .map(|mx| {
                    (mx.preference(), mx.exchange().to_utf8())
                })
                .collect();
            
            mx_hosts.sort_by_key(|k| k.0);
            
            if mx_hosts.is_empty() {
                println!("    {} No MX records found", "✗".red());
                result.mx_issues.push("No MX records found".to_string());
                return Ok(());
            }
            
            println!("    {} Found {} MX record(s)", "✓".green(), mx_hosts.len());
            for (pref, host) in &mx_hosts {
                println!("      {} (priority: {})", host, pref);
                result.mx_records.push(format!("{} ({})", host, pref));
            }
            
            // Check first MX server (highest priority)
            if let Some((_, mx_host)) = mx_hosts.first() {
                println!("  {} SMTP on primary MX: {}", "Checking".blue(), mx_host);
                check_smtp_server(resolver, mx_host, result, verbose).await?;
            }
        },
        Err(e) => {
            if verbose {
                eprintln!("[VERBOSE] MX lookup failed: {}", e);
            }
            println!("    {} No MX records found", "✗".red());
            result.mx_issues.push("MX lookup failed".to_string());
        }
    }
    
    Ok(())
}

/// Check SMTP server (reverse DNS, banner, TLS, relay, blacklist)
async fn check_smtp_server(
    resolver: &TokioAsyncResolver,
    mx_host: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;
    
    // Resolve MX to IP
    let mx_ips = match resolver.lookup_ip(mx_host).await {
        Ok(lookup) => lookup.iter().collect::<Vec<_>>(),
        Err(e) => {
            if verbose {
                eprintln!("[VERBOSE] Failed to resolve MX host {}: {}", mx_host, e);
            }
            result.mx_issues.push(format!("Failed to resolve MX host: {}", mx_host));
            return Ok(());
        }
    };
    
    if mx_ips.is_empty() {
        return Ok(());
    }
    
    let mx_ip = mx_ips[0];
    
    let mut smtp_result = SmtpCheckResult {
        mx_host: mx_host.to_string(),
        mx_ip: mx_ip.to_string(),
        reverse_dns: None,
        reverse_dns_valid: false,
        smtp_banner: None,
        banner_matches_rdns: false,
        supports_tls: false,
        is_open_relay: false,
        issues: Vec::new(),
    };
    
    // Check reverse DNS
    match resolver.reverse_lookup(mx_ip).await {
        Ok(lookup) => {
            if let Some(ptr) = lookup.iter().next() {
                let rdns = ptr.to_utf8();
                smtp_result.reverse_dns = Some(rdns.clone());
                
                // Validate reverse DNS (should be a valid hostname)
                if rdns.contains('.') && !rdns.chars().all(|c| c.is_numeric() || c == '.') {
                    smtp_result.reverse_dns_valid = true;
                    println!("    {} Reverse DNS: {}", "✓".green(), rdns);
                } else {
                    smtp_result.issues.push("Reverse DNS is not a valid hostname".to_string());
                    println!("    {} Reverse DNS invalid: {}", "⚠".yellow(), rdns);
                }
            } else {
                smtp_result.issues.push("No reverse DNS record".to_string());
                println!("    {} No reverse DNS record", "✗".yellow());
            }
        },
        Err(_) => {
            smtp_result.issues.push("Reverse DNS lookup failed".to_string());
            println!("    {} No reverse DNS record", "✗".yellow());
        }
    }
    
    // Connect to SMTP server
    let addr = format!("{}:25", mx_ip);
    match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buffer = vec![0u8; 1024];
            
            // Read SMTP banner
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                    smtp_result.smtp_banner = Some(banner.clone());
                    
                    if verbose {
                        eprintln!("[VERBOSE] SMTP banner: {}", banner);
                    }
                    
                    println!("    {} SMTP banner received", "✓".green());
                    
                    // Check if banner matches reverse DNS
                    if let Some(rdns) = &smtp_result.reverse_dns {
                        if banner.to_lowercase().contains(&rdns.to_lowercase()) || 
                           rdns.to_lowercase().contains(&banner.to_lowercase().split_whitespace().last().unwrap_or("")) {
                            smtp_result.banner_matches_rdns = true;
                            println!("    {} Banner matches reverse DNS", "✓".green());
                        } else {
                            smtp_result.issues.push("SMTP banner does not match reverse DNS".to_string());
                            println!("    {} Banner does not match reverse DNS", "⚠".yellow());
                        }
                    }
                    
                    // Check TLS support (STARTTLS)
                    let ehlo_cmd = format!("EHLO test.example.com\r\n");
                    if stream.write_all(ehlo_cmd.as_bytes()).await.is_ok() {
                        let mut ehlo_buffer = vec![0u8; 2048];
                        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut ehlo_buffer)).await {
                            let ehlo_response = String::from_utf8_lossy(&ehlo_buffer[..n]);
                            if ehlo_response.to_uppercase().contains("STARTTLS") {
                                smtp_result.supports_tls = true;
                                println!("    {} Supports STARTTLS", "✓".green());
                            } else {
                                smtp_result.issues.push("Does not support STARTTLS".to_string());
                                println!("    {} No STARTTLS support", "⚠".yellow());
                            }
                            
                            // Check for open relay (basic test)
                            let mail_from = "MAIL FROM:<test@example.com>\r\n";
                            if stream.write_all(mail_from.as_bytes()).await.is_ok() {
                                let mut mail_buffer = vec![0u8; 512];
                                if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut mail_buffer)).await {
                                    let mail_response = String::from_utf8_lossy(&mail_buffer[..n]);
                                    if mail_response.starts_with("250") {
                                        let rcpt_to = "RCPT TO:<test@external-domain.com>\r\n";
                                        if stream.write_all(rcpt_to.as_bytes()).await.is_ok() {
                                            let mut rcpt_buffer = vec![0u8; 512];
                                            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut rcpt_buffer)).await {
                                                let rcpt_response = String::from_utf8_lossy(&rcpt_buffer[..n]);
                                                if rcpt_response.starts_with("250") {
                                                    smtp_result.is_open_relay = true;
                                                    smtp_result.issues.push("CRITICAL: Possible open relay detected".to_string());
                                                    println!("    {} CRITICAL: Possible open relay!", "⚠".red());
                                                } else {
                                                    println!("    {} Not an open relay", "✓".green());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Send QUIT
                    let _ = stream.write_all(b"QUIT\r\n").await;
                },
                _ => {
                    smtp_result.issues.push("Failed to read SMTP banner".to_string());
                    println!("    {} Failed to read SMTP banner", "✗".yellow());
                }
            }
        },
        _ => {
            smtp_result.issues.push("Failed to connect to SMTP server".to_string());
            println!("    {} Failed to connect to SMTP server", "✗".yellow());
        }
    }
    
    // Check blacklists
    println!("  {} Blacklists...", "Checking".blue());
    check_blacklists(resolver, &mx_ip.to_string(), result, verbose).await?;
    
    result.smtp_checks.push(smtp_result);
    
    Ok(())
}

/// Check if IP is blacklisted
async fn check_blacklists(
    resolver: &TokioAsyncResolver,
    ip: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    // Common blacklists to check
    let blacklists = vec![
        ("zen.spamhaus.org", "Spamhaus ZEN"),
        ("bl.spamcop.net", "SpamCop"),
        ("b.barracudacentral.org", "Barracuda"),
        ("dnsbl.sorbs.net", "SORBS"),
    ];
    
    // Reverse IP for DNSBL query (e.g., 1.2.3.4 -> 4.3.2.1)
    let reversed_ip = ip.split('.')
        .rev()
        .collect::<Vec<_>>()
        .join(".");
    
    let mut listed_count = 0;
    
    for (bl_domain, bl_name) in blacklists {
        let query = format!("{}.{}", reversed_ip, bl_domain);
        
        if verbose {
            eprintln!("[VERBOSE] Checking blacklist: {}", bl_name);
        }
        
        let is_listed = match resolver.lookup_ip(&query).await {
            Ok(_) => {
                // If lookup succeeds, IP is listed
                listed_count += 1;
                println!("    {} Listed on {}", "✗".red(), bl_name);
                true
            },
            Err(_) => {
                // If lookup fails, IP is not listed
                if verbose {
                    eprintln!("[VERBOSE] Not listed on {}", bl_name);
                }
                false
            }
        };
        
        result.blacklist_results.push(BlacklistResult {
            ip: ip.to_string(),
            blacklist_name: bl_name.to_string(),
            is_listed,
        });
    }
    
    if listed_count == 0 {
        println!("    {} Not listed on checked blacklists", "✓".green());
    } else {
        result.mx_issues.push(format!("IP listed on {} blacklist(s)", listed_count));
    }
    
    Ok(())
}

/// Check if domain is blacklisted (RHSBL - Right Hand Side Blacklist)
async fn check_domain_blacklists(
    resolver: &TokioAsyncResolver,
    domain: &str,
    result: &mut EmailVerificationResult,
    verbose: bool,
) -> Result<()> {
    // Common domain blacklists (RHSBL)
    let domain_blacklists = vec![
        ("dbl.spamhaus.org", "Spamhaus DBL"),
        ("rhsbl.sorbs.net", "SORBS RHSBL"),
        ("multi.surbl.org", "SURBL Multi"),
    ];
    
    let mut listed_count = 0;
    
    for (bl_domain, bl_name) in domain_blacklists {
        let query = format!("{}.{}", domain, bl_domain);
        
        if verbose {
            eprintln!("[VERBOSE] Checking domain blacklist: {}", bl_name);
        }
        
        let is_listed = match resolver.lookup_ip(&query).await {
            Ok(_) => {
                // If lookup succeeds, domain is listed
                listed_count += 1;
                println!("    {} Listed on {}", "✗".red(), bl_name);
                true
            },
            Err(_) => {
                // If lookup fails, domain is not listed
                if verbose {
                    eprintln!("[VERBOSE] Not listed on {}", bl_name);
                }
                false
            }
        };
        
        result.blacklist_results.push(BlacklistResult {
            ip: domain.to_string(), // Using domain field for domain blacklists
            blacklist_name: format!("{} (domain)", bl_name),
            is_listed,
        });
    }
    
    if listed_count == 0 {
        println!("    {} Domain not listed on checked blacklists", "✓".green());
    } else {
        result.mx_issues.push(format!("Domain listed on {} blacklist(s)", listed_count));
    }
    
    Ok(())
}

/// Save email verification results to file
fn save_email_verification_results(
    result: &EmailVerificationResult,
    output_dir: &str,
) -> Result<()> {
    use std::fs;
    use std::io::Write;
    
    // Ensure output directory exists
    if !std::path::Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir).context("Failed to create output directory")?;
    }
    
    let safe_domain = crate::utils::sanitize_for_filename(&result.domain);
    let output_file = format!("{}/email_verification_{}.txt", output_dir, safe_domain);
    
    let mut file = fs::File::create(&output_file)
        .context(format!("Failed to create file: {}", output_file))?;
    
    writeln!(file, "Email DNS Verification Results for: {}", result.domain)?;
    writeln!(file, "{}", "=".repeat(70))?;
    writeln!(file)?;
    
    // SPF Section
    writeln!(file, "SPF (Sender Policy Framework)")?;
    writeln!(file, "{}", "-".repeat(70))?;
    if result.spf_present {
        writeln!(file, "Status: PRESENT")?;
        if let Some(record) = &result.spf_record {
            writeln!(file, "Record: {}", record)?;
        }
    } else {
        writeln!(file, "Status: NOT FOUND")?;
    }
    
    if !result.spf_issues.is_empty() {
        writeln!(file, "\nIssues:")?;
        for issue in &result.spf_issues {
            writeln!(file, "  - {}", issue)?;
        }
    }
    writeln!(file)?;
    
    // DMARC Section
    writeln!(file, "DMARC (Domain-based Message Authentication)")?;
    writeln!(file, "{}", "-".repeat(70))?;
    if result.dmarc_present {
        writeln!(file, "Status: PRESENT")?;
        if let Some(record) = &result.dmarc_record {
            writeln!(file, "Record: {}", record)?;
        }
    } else {
        writeln!(file, "Status: NOT FOUND")?;
    }
    
    if !result.dmarc_issues.is_empty() {
        writeln!(file, "\nIssues:")?;
        for issue in &result.dmarc_issues {
            writeln!(file, "  - {}", issue)?;
        }
    }
    writeln!(file)?;
    
    // DKIM Section
    writeln!(file, "DKIM (DomainKeys Identified Mail)")?;
    writeln!(file, "{}", "-".repeat(70))?;
    if !result.dkim_selectors_found.is_empty() {
        writeln!(file, "Status: PRESENT")?;
        writeln!(file, "Selectors found: {}", result.dkim_selectors_found.join(", "))?;
    } else {
        writeln!(file, "Status: NOT FOUND (checked common selectors)")?;
    }
    
    if !result.dkim_issues.is_empty() {
        writeln!(file, "\nIssues:")?;
        for issue in &result.dkim_issues {
            writeln!(file, "  - {}", issue)?;
        }
    }
    writeln!(file)?;
    
    // MX Section
    writeln!(file, "MX (Mail Exchange) Records")?;
    writeln!(file, "{}", "-".repeat(70))?;
    if !result.mx_records.is_empty() {
        writeln!(file, "Status: PRESENT")?;
        writeln!(file, "Records:")?;
        for mx in &result.mx_records {
            writeln!(file, "  - {}", mx)?;
        }
    } else {
        writeln!(file, "Status: NOT FOUND")?;
    }
    
    if !result.mx_issues.is_empty() {
        writeln!(file, "\nIssues:")?;
        for issue in &result.mx_issues {
            writeln!(file, "  - {}", issue)?;
        }
    }
    writeln!(file)?;
    
    // SMTP Checks Section
    if !result.smtp_checks.is_empty() {
        writeln!(file, "SMTP Server Checks")?;
        writeln!(file, "{}", "-".repeat(70))?;
        for smtp in &result.smtp_checks {
            writeln!(file, "MX Host: {}", smtp.mx_host)?;
            writeln!(file, "IP: {}", smtp.mx_ip)?;
            
            if let Some(rdns) = &smtp.reverse_dns {
                writeln!(file, "Reverse DNS: {} (valid: {})", rdns, smtp.reverse_dns_valid)?;
            } else {
                writeln!(file, "Reverse DNS: NOT FOUND")?;
            }
            
            if let Some(banner) = &smtp.smtp_banner {
                writeln!(file, "SMTP Banner: {}", banner)?;
                writeln!(file, "Banner matches rDNS: {}", smtp.banner_matches_rdns)?;
            }
            
            writeln!(file, "Supports TLS (STARTTLS): {}", smtp.supports_tls)?;
            writeln!(file, "Open Relay: {}", smtp.is_open_relay)?;
            
            if !smtp.issues.is_empty() {
                writeln!(file, "Issues:")?;
                for issue in &smtp.issues {
                    writeln!(file, "  - {}", issue)?;
                }
            }
            writeln!(file)?;
        }
    }
    
    // Blacklist Section
    if !result.blacklist_results.is_empty() {
        writeln!(file, "Blacklist Checks")?;
        writeln!(file, "{}", "-".repeat(70))?;
        let listed_count = result.blacklist_results.iter().filter(|bl| bl.is_listed).count();
        writeln!(file, "Listed on {} of {} checked blacklists", listed_count, result.blacklist_results.len())?;
        writeln!(file)?;
        for bl in &result.blacklist_results {
            if bl.is_listed {
                writeln!(file, "  ✗ {} - LISTED", bl.blacklist_name)?;
            } else {
                writeln!(file, "  ✓ {} - Not listed", bl.blacklist_name)?;
            }
        }
        writeln!(file)?;
    }
    
    // Summary
    writeln!(file, "Summary")?;
    writeln!(file, "{}", "-".repeat(70))?;
    let total_issues = result.spf_issues.len() + result.dmarc_issues.len() + result.dkim_issues.len() + result.mx_issues.len();
    let smtp_issues: usize = result.smtp_checks.iter().map(|s| s.issues.len()).sum();
    let blacklist_count = result.blacklist_results.iter().filter(|bl| bl.is_listed).count();
    writeln!(file, "Total issues found: {}", total_issues + smtp_issues)?;
    writeln!(file, "Blacklists: {}", blacklist_count)?;
    
    println!("{} Results saved to: {}", "✓".green(), output_file);
    
    Ok(())
}

/// Run email verification on all provided domains
pub async fn run_email_verification(
    domains: &[String],
    output_dir: &str,
    verbose: bool,
) -> Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    
    println!("\n{}", "=".repeat(70).blue().bold());
    println!("{}", "  EMAIL DNS VERIFICATION".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    println!("Verifying email DNS records for {} domain(s)", domains.len());
    println!("{}", "-".repeat(70));
    
    for domain in domains {
        let result = verify_email_dns(domain, verbose).await?;
        save_email_verification_results(&result, output_dir)?;
        println!();
    }
    
    println!("{}", "=".repeat(70).blue().bold());
    println!("{}", "  EMAIL VERIFICATION COMPLETE".blue().bold());
    println!("{}", "=".repeat(70).blue().bold());
    
    Ok(())
}
