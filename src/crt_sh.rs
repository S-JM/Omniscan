use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use colored::*;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn fetch_subdomains(domain: &str) -> Result<Vec<String>> {
    println!("{}", format!("Querying crt.sh for {}...", domain).blue());

    let client = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .timeout(Duration::from_secs(30))
        .build()?;

    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    
    let response = client.get(&url).send().await?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to query crt.sh: Status {}", response.status()));
    }

    // crt.sh sometimes returns invalid JSON or empty body on error/rate limit, 
    // but reqwest::json() should handle the parsing error if it's not valid JSON.
    // However, sometimes it returns a huge list.
    
    let entries: Vec<CrtShEntry> = response.json().await?;
    
    let mut subdomains = HashSet::new();
    let domain_suffix = format!(".{}", domain);
    
    for entry in entries {
        // crt.sh can return multiple domains in one entry separated by newlines
        for line in entry.name_value.lines() {
            let sub = line.trim().to_lowercase();
            
            // Filter out wildcards, emails, and spaces (common in cert names)
            if !sub.contains('*') && !sub.contains('@') && !sub.contains(' ') {
                // Ensure it matches domain exactly or ends with .domain (to avoid matching testexample.com for example.com)
                if sub == domain || sub.ends_with(&domain_suffix) {
                    subdomains.insert(sub);
                }
            }
        }
    }

    let mut result: Vec<String> = subdomains.into_iter().collect();
    result.sort();
    
    Ok(result)
}
