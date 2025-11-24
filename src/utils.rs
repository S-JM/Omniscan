use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn read_lines<P>(filename: P) -> Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(&filename).with_context(|| format!("Failed to open file: {:?}", filename.as_ref()))?;
    let lines = io::BufReader::new(file).lines();
    let mut result = Vec::new();
    for line in lines {
        let line = line?;
        if !line.trim().is_empty() {
            result.push(line.trim().to_string());
        }
    }
    Ok(result)
}

/// Sanitizes a domain or target name for use in filenames.
///
/// Replaces characters that are invalid or problematic in filenames
/// (colons and slashes) with underscores.
///
/// # Arguments
/// * `input` - The string to sanitize (domain, IP, or target name)
///
/// # Returns
/// A sanitized string safe for use in filenames
///
/// # Examples
/// ```
/// let safe = sanitize_for_filename("example.com:443");
/// assert_eq!(safe, "example.com_443");
/// ```
pub fn sanitize_for_filename(input: &str) -> String {
    input.replace(":", "_").replace("/", "_")
}


