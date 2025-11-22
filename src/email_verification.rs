/// Email DNS verification module for SPF, DMARC, and DKIM records
use anyhow::{Context, Result};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
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
    };
    
    // Check SPF
    println!("  {} SPF record...", "Checking".blue());
    check_spf(&resolver, domain, &mut result, verbose).await?;
    
    // Check DMARC
    println!("  {} DMARC record...", "Checking".blue());
    check_dmarc(&resolver, domain, &mut result, verbose).await?;
    
    // Check DKIM
    println!("  {} DKIM records...", "Checking".blue());
    check_dkim(&resolver, domain, &mut result, verbose).await?;
    
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
    
    let safe_domain = result.domain.replace(":", "_").replace("/", "_");
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
    
    // Summary
    writeln!(file, "Summary")?;
    writeln!(file, "{}", "-".repeat(70))?;
    let total_issues = result.spf_issues.len() + result.dmarc_issues.len() + result.dkim_issues.len();
    writeln!(file, "Total issues found: {}", total_issues)?;
    
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
