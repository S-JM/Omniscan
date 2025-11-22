# Omniscan

Automated Nmap scanning with SSL/TLS analysis, DNS zone transfers, email security verification, and subdomain enumeration.

## Features

### Core Scanning
*   Scan sequence: Host discovery → TCP scan → UDP scan → Service/script scan
*   Host discovery: ICMP, TCP SYN/ACK, UDP probes
*   Firewall evasion: Fragmentation, source port manipulation, bad checksums
*   UDP: Top 1000 ports + DHCP, TFTP, Syslog

### DNS & Domain
*   AXFR zone transfers
*   Subdomain fuzzing with DNS resolution
*   Discovered hosts added to scan targets

### Email Security
*   SPF: Syntax validation, policy checks, DNS lookup count
*   DMARC: Policy verification, reporting configuration
*   DKIM: Common selector checks
*   MX: Record discovery and validation
*   Reverse DNS validation
*   SMTP banner verification
*   STARTTLS detection
*   Open relay testing
*   Blacklists:
  - DNSBL: Spamhaus ZEN, SpamCop, Barracuda, SORBS
  - RHSBL: Spamhaus DBL, SORBS RHSBL, SURBL Multi

### SSL/TLS
*   testssl.sh integration (GPLv2)
*   Scans discovered SSL/TLS services
*   JSON output: ciphers, protocols, vulnerabilities, certificates

### Usability
*   Colored output
*   XML (default) or all Nmap formats
*   Dry-run mode
*   Modes: `--testssl-only`, `--zone-transfer-only`, `--email-verification-only`, `--skip-fuzzing`
*   `--yes-all` for unattended execution

## Prerequisites

*   `nmap` in PATH
*   Bash (Linux/macOS) or WSL/Git Bash (Windows) for testssl.sh

## Installation

### Binary
1.  Download from [Releases](../../releases)
2.  `chmod +x omniscan` (Linux/macOS)

### Build
```bash
cargo build --release
# Binary: target/release/omniscan
```

## Usage

```bash
# Basic
./omniscan 192.168.1.1

# All formats
./omniscan --all-formats 192.168.1.1

# Dry-run
./omniscan --dry-run 192.168.1.1

# Subdomain fuzzing
./omniscan example.com --wordlist subdomains.txt

# SSL/TLS scan
./omniscan --testssl 192.168.1.0/24

# SSL/TLS only
./omniscan --testssl-only example.com

# Zone transfer only
./omniscan --zone-transfer-only example.com

# Email verification only
./omniscan --email-verification-only example.com

# Skip fuzzing
./omniscan --skip-fuzzing example.com --wordlist subdomains.txt

# Unattended
./omniscan --yes-all 192.168.1.0/24

# From file
./omniscan -i targets.txt

# Output directory
./omniscan --output-dir ./results 192.168.1.1
```

## Output Files

- `alive_hosts.txt`
- `tcp_scan.xml`
- `udp_scan.xml`
- `service_scan.xml`
- `testssl_<target>.json`
- `zone_transfer_<domain>.txt`
- `email_verification_<domain>.txt`
- `found_subdomains.txt`

## Third-Party Components

Embeds [testssl.sh](https://github.com/drwetter/testssl.sh) v3.0.4 (GPLv2) by Dirk Wetter.

## License

MIT License. See [LICENSE](LICENSE).

testssl.sh component: GPLv2.



