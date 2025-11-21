/// Embedded assets for testssl.sh integration
use std::fs;
use std::path::PathBuf;
use anyhow::{Context, Result};
use tempfile::TempDir;
use std::process::Command as StdCommand;

/// Embedded testssl.sh tarball (v3.0.4 complete package)
const TESTSSL_TARBALL: &[u8] = include_bytes!("resources/testssl-3.0.4.tar.gz");

/// Embedded OpenSSL 1.1.1 static binary (Linux x86_64)
const OPENSSL_BINARY: &[u8] = include_bytes!("resources/openssl");

/// Extracts embedded testssl.sh package to a temporary directory
/// Returns a tuple: (temp_dir, testssl_dir, testssl_script_path, openssl_path)
pub fn extract_assets() -> Result<(TempDir, PathBuf, PathBuf, PathBuf)> {
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    
    // Write tarball to temp location
    let tarball_path = temp_dir.path().join("testssl.tar.gz");
    fs::write(&tarball_path, TESTSSL_TARBALL)
        .context("Failed to write testssl tarball")?;
    
    // Extract tarball using tar command (requires tar to be available)
    let output = StdCommand::new("tar")
        .args(&["-xzf", tarball_path.to_str().unwrap(), "-C", temp_dir.path().to_str().unwrap()])
        .output()
        .context("Failed to execute tar command - is tar installed?")?;
    
    if !output.status.success() {
        anyhow::bail!(
            "Failed to extract testssl tarball: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    
    // The extracted directory is testssl.sh-3.0.4
    let testssl_dir = temp_dir.path().join("testssl.sh-3.0.4");
    let testssl_script = testssl_dir.join("testssl.sh");
    
    // Write openssl binary to the bin directory
    let bin_dir = testssl_dir.join("bin");
    fs::create_dir_all(&bin_dir).context("Failed to create bin directory")?;
    let openssl_path = bin_dir.join("openssl");
    fs::write(&openssl_path, OPENSSL_BINARY)
        .context("Failed to write openssl binary")?;
    
    // Make files executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        
        let mut perms = fs::metadata(&testssl_script)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&testssl_script, perms)?;
        
        let mut perms = fs::metadata(&openssl_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&openssl_path, perms)?;
    }
    
    Ok((temp_dir, testssl_dir, testssl_script, openssl_path))
}
