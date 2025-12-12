
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub output_dir: String,
    pub dry_run: bool,
    pub verbose: bool,
    pub all_formats: bool,
    pub yes_all: bool,
    pub wordlist: Option<String>,
    pub strict_scope: bool,
    
    // Explicit run flags
    pub run_port_scan: bool,
    pub run_testssl: bool,
    pub run_fuzzing: bool,
    pub run_zone_transfer: bool,
    pub run_email_verification: bool,
    pub run_crt_sh: bool,

    // Port scan customization
    pub custom_nmap_args: Option<String>,
    pub firewall_evasion: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            output_dir: ".".to_string(),
            dry_run: false,
            verbose: false,
            all_formats: false,
            yes_all: false,
            wordlist: None,
            strict_scope: true,
            
            // Default to nothing running, must be explicitly enabled
            run_port_scan: false,
            run_testssl: false,
            run_fuzzing: false,
            run_zone_transfer: false,
            run_email_verification: false,
            run_crt_sh: false,

            custom_nmap_args: None,
            firewall_evasion: false,
        }
    }
}
