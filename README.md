# Nmap Helper

An automated Nmap scanning tool written in Rust. It helps perform Nmap scans for a huge scope of targets, performs subdomain fuzzing, and implements progressive firewall evasion techniques.

## Features

*   **Automated Scan Orchestration**: Runs a sequence of scans: Alive Host Discovery -> TCP Port Scan -> UDP Port Scan -> Service & Script Scan.
*   **Smart Host Discovery**: Uses multiple techniques (ICMP, TCP SYN/ACK, UDP) to detect hosts behind firewalls.
*   **Progressive Firewall Evasion**: Automatically detects hosts with few open ports and interactively offers evasion techniques (fragmentation, source ports, bad checksums, etc.).
*   **High-Value UDP Scanning**: Scans top 1000 UDP ports plus critical services like DHCP, TFTP, Syslog, etc.
*   **Subdomain Fuzzing**: Integrated subdomain enumeration and DNS resolution.
*   **Flexible Output**: Supports XML (default) and all Nmap formats (`-oA`), with organized file naming.
*   **Dry-Run Mode**: Preview commands before execution.

## Prerequisites

*   **Nmap**: `nmap` must be installed and in your system's PATH.

## Installation

### Option 1: Download Binary (Preferred)

1.  Download the latest release binary for your platform from the [Releases](../../releases) page.
2.  Make the binary executable (Linux/macOS):
    ```bash
    chmod +x nmap_helper
    ```
3.  Run it directly!

### Option 2: Build from Source

**Prerequisites:**
*   **Rust**: You need the Rust toolchain installed (cargo, rustc). [Install Rust](https://www.rust-lang.org/tools/install)

**Steps:**
1.  Clone the repository (if applicable) or navigate to the project directory.
2.  Build the project using Cargo:
    ```bash
    cargo build --release
    ```
3.  The executable will be located in `target/release/nmap_helper` (or `nmap_helper.exe` on Windows).

## Usage

```bash
# Basic scan of a target IP or CIDR
./nmap_helper 192.168.1.1

# Scan with all output formats enabled
./nmap_helper --all-formats 192.168.1.1

# Dry-run mode (preview commands)
./nmap_helper --dry-run 192.168.1.1

# Subdomain fuzzing
./nmap_helper --domain example.com --wordlist subdomains.txt

# Scan targets from a file (one target per line)
./nmap_helper -i targets.txt
```

## AI Assistance

This project was designed and coded with the assistance of AI.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
