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
/// use omniscan::utils::sanitize_for_filename;
/// let safe = sanitize_for_filename("example.com:443");
/// assert_eq!(safe, "example.com_443");
/// ```
pub fn sanitize_for_filename(input: &str) -> String {
    input.replace(":", "_").replace("/", "_")
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_sanitize_for_filename_with_colon() {
        assert_eq!(sanitize_for_filename("example.com:443"), "example.com_443");
    }

    #[test]
    fn test_sanitize_for_filename_with_slash() {
        assert_eq!(sanitize_for_filename("path/to/file"), "path_to_file");
    }

    #[test]
    fn test_sanitize_for_filename_with_both() {
        assert_eq!(
            sanitize_for_filename("http://example.com:80/path"),
            "http___example.com_80_path"
        );
    }

    #[test]
    fn test_sanitize_for_filename_normal_string() {
        assert_eq!(sanitize_for_filename("normal.txt"), "normal.txt");
    }

    #[test]
    fn test_sanitize_for_filename_empty_string() {
        assert_eq!(sanitize_for_filename(""), "");
    }

    #[test]
    fn test_sanitize_for_filename_multiple_colons() {
        assert_eq!(sanitize_for_filename("a:b:c:d"), "a_b_c_d");
    }

    #[test]
    fn test_read_lines_valid_file() {
        // Create a temporary file for testing
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "line1").unwrap();
        writeln!(temp_file, "line2").unwrap();
        writeln!(temp_file, "").unwrap(); // Empty line should be skipped
        writeln!(temp_file, "  line3  ").unwrap(); // Line with spaces should be trimmed

        let lines = read_lines(temp_file.path()).unwrap();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[1], "line2");
        assert_eq!(lines[2], "line3"); // Trimmed
    }

    #[test]
    fn test_read_lines_empty_file() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let lines = read_lines(temp_file.path()).unwrap();
        assert_eq!(lines.len(), 0);
    }

    #[test]
    fn test_read_lines_only_empty_lines() {
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(temp_file, "").unwrap();
        writeln!(temp_file, "   ").unwrap();
        writeln!(temp_file, "").unwrap();

        let lines = read_lines(temp_file.path()).unwrap();
        assert_eq!(lines.len(), 0);
    }

    #[test]
    fn test_read_lines_nonexistent_file() {
        let result = read_lines("/nonexistent/path/to/file.txt");
        assert!(result.is_err());
    }
}

