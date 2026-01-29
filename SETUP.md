# 🔮 ShadowRecon v3.0.1 - Setup Guide

A step-by-step guide to get ShadowRecon running from scratch.

> ⚠️ **IMPORTANT**: All scans are routed through Tor network. Tor must be running before using ShadowRecon.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.8+ | Required |
| **Nmap** | Latest | Required for port scanning |
| **Tor** | Latest | MANDATORY - all scans require Tor |
| **Git** | Any | Optional, for cloning |

---

## Step 1: Clone or Download

```bash
git clone https://github.com/mba-x86/ShadowRecon.git
cd ShadowRecon
```

Or download and extract the ZIP file from the repository.

---

## Step 2: Create Virtual Environment (Recommended)

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs all required packages including:
- `python-nmap` - Network scanning
- `paramiko`, `asyncssh` - SSH testing
- `PySocks`, `stem` - Tor integration
- `cryptography` - Crypto analysis
- `dnspython` - DNS utilities
- `pytest` - Testing

---

## Step 4: Install Nmap

**Windows:**
1. Download from https://nmap.org/download.html
2. Run the installer
3. Ensure "Add to PATH" is selected during installation

**Linux:**
```bash
sudo apt install nmap        # Debian/Ubuntu
sudo yum install nmap        # CentOS/RHEL
sudo pacman -S nmap          # Arch
```

**Mac:**
```bash
brew install nmap
```

**Verify installation:**
```bash
nmap --version
```

---

## Step 5: Install and Start Tor (MANDATORY)

ShadowRecon requires Tor for ALL scans - no exposed scans are allowed.

### Windows

**Option 1: Tor Browser (Easiest)**
1. Download from https://www.torproject.org/download/
2. Install and launch Tor Browser
3. Keep it running while using ShadowRecon
4. ShadowRecon auto-detects Tor Browser on port 9150

**Option 2: Tor Expert Bundle**
1. Download from https://www.torproject.org/download/tor/
2. Extract to a folder (e.g., `C:\Tor`)
3. Run `tor.exe`
4. Uses port 9050 by default

**Option 3: Chocolatey**
```powershell
choco install tor
```

### Linux

```bash
# Install
sudo apt install tor         # Debian/Ubuntu
sudo yum install tor         # CentOS/RHEL
sudo pacman -S tor           # Arch

# Start service
sudo systemctl start tor
sudo systemctl enable tor    # Auto-start on boot

# Verify
sudo systemctl status tor
```

### Mac

```bash
brew install tor
brew services start tor
```

### Verify Tor is Running

```bash
python main.py --check-tor
```

Expected output when Tor is ready:
```
==================================================
🧅 TOR STATUS CHECK
==================================================
Installed: ✅
  Path: /usr/bin/tor
Running: ✅
Type: Standalone Tor
SOCKS Port (9050): ✅ (SOCKS5 verified)
Control Port (9051): ✅

✅ Tor is ready! ShadowRecon will use it automatically.
==================================================
```

---

## Step 6: Configuration (Optional)

Edit `config.yaml` to customize scan settings:

```yaml
general:
  timeout: 10        # Base timeout (Tor adds ~3x latency automatically)
  verbose: false     # Enable detailed output
  max_threads: 100   # Concurrent threads

port_scanner:
  default_range: "common"  # common, vpn, all

reports:
  output_dir: "./reports"
  formats:
    - json
    - markdown
```

---

## Step 7: Run the Tool

> 🧅 **Tor is mandatory** - ShadowRecon will not run without an active Tor connection.
> If Tor is installed but not running, ShadowRecon will attempt to start it automatically.

### Basic Usage

```bash
# Check Tor status first
python main.py --check-tor

# Scan a target
python main.py 192.168.1.1

# Scan with verbose output
python main.py example.com --verbose

# Scan with custom timeout
python main.py 10.0.0.1 --timeout 15
```

### Advanced Usage

```bash
# VPN-focused scan (faster, targets VPN ports only)
python main.py 192.168.1.1 --port-range vpn

# Custom SSH port
python main.py example.com --ssh-port 2222

# WireGuard config analysis
python main.py 10.0.0.1 --wg-port 51821 --wg-config /etc/wireguard/wg0.conf

# Skip specific scans for faster results
python main.py 192.168.1.1 --skip-dns --skip-banner

# Enable brute force testing (AUTHORIZED USE ONLY)
python main.py 192.168.1.1 --brute-force --brute-max-attempts 5

# Custom Tor port (if not auto-detected)
python main.py 192.168.1.1 --tor-port 9150
```

### Using Helper Scripts

**Windows:**
```cmd
run_scan.bat 192.168.1.1
```

**Linux/Mac:**
```bash
chmod +x run_scan.sh
./run_scan.sh 192.168.1.1
```

---

## Step 8: View Reports

Reports are saved in target-specific folders:

```
reports/
└── <target>/
    └── <timestamp>/
        ├── report.json    # Machine-readable format
        └── report.md      # Human-readable markdown
```

---

## Step 9: Run Tests (Optional)

```bash
python -m pytest tests/ -v
```

---

## Quick Reference

### All Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target IP/hostname | Required |
| `-v, --verbose` | Detailed output | False |
| `-t, --timeout` | Connection timeout (seconds) | 10 |
| `-o, --output-dir` | Report output directory | ./reports |
| `--port-range` | `common`, `vpn`, `all`, or `1-1000` | common |
| `--ssh-port` | SSH port | 22 |
| `--wg-port` | WireGuard port | 51820 |
| `--wg-config` | WireGuard config file path | None |
| `--domain` | Domain for DNS scanning | None |
| `--tor-port` | Custom Tor SOCKS port | Auto-detect |
| `--tor-control-port` | Tor control port for IP rotation | Auto-detect |
| `--check-tor` | Check Tor status and exit | - |
| `--brute-force` | Enable brute force testing | False |
| `--brute-service` | Service: `ssh` or `ftp` | ssh |
| `--brute-max-attempts` | Max brute force attempts | 10 |

### Skip Options

| Option | Description |
|--------|-------------|
| `--skip-port` | Skip port scanning |
| `--skip-ssh` | Skip SSH scanning |
| `--skip-softether` | Skip SoftEther scanning |
| `--skip-wireguard` | Skip WireGuard scanning |
| `--skip-ssl` | Skip SSL/TLS scanning |
| `--skip-vulnerability` | Skip vulnerability scanning |
| `--skip-banner` | Skip banner grabbing |
| `--skip-dns` | Skip DNS scanning |
| `--skip-brute` | Skip brute force (default: True) |

---

## Troubleshooting

### "FATAL: Cannot proceed without Tor connection"

1. Check Tor status: `python main.py --check-tor`
2. If "Installed: ✅" but "Running: ❌":
   - **Windows**: Start Tor Browser or run `tor.exe`
   - **Linux**: `sudo systemctl start tor`
   - **Mac**: `brew services start tor`
3. If using Tor Browser, ensure it's open and connected
4. Try specifying the port manually:
   - Tor Browser: `--tor-port 9150`
   - Standalone Tor: `--tor-port 9050`

### "nmap not found"

- Install Nmap and add to system PATH
- Restart terminal after installation
- Verify: `nmap --version`

### Permission denied (Linux)

```bash
# Some scans may need root for raw sockets
sudo python main.py <target>
```

### Module not found

```bash
# Ensure you're in the virtual environment
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Slow scans

- Tor adds ~3x latency (timeouts are automatically adjusted)
- Use `--port-range vpn` for faster VPN-focused scans
- Use `--skip-*` options to disable unnecessary scanners
- Increase timeout if scans are timing out: `--timeout 20`

### Tests failing

```bash
# Install test dependencies
pip install pytest

# Run tests with verbose output
python -m pytest tests/ -v --tb=long
```

---

## Environment Variables

ShadowRecon respects these environment variables:

| Variable | Description |
|----------|-------------|
| `TOR_SOCKS_PORT` | Override Tor SOCKS port |
| `TOR_CONTROL_PORT` | Override Tor control port |

---

## Project Structure

```
ShadowRecon/
├── main.py              # Entry point
├── version.py           # Version info
├── tor_manager.py       # Tor network management
├── report_generator.py  # JSON/Markdown reports
├── config.yaml          # Configuration
├── requirements.txt     # Dependencies
├── run_scan.bat         # Windows helper
├── run_scan.sh          # Linux/Mac helper
├── scanners/            # Scanner modules
│   ├── base_scanner.py
│   ├── port_scanner.py
│   ├── ssh_scanner.py
│   ├── softether_scanner.py
│   ├── wireguard_scanner.py
│   ├── ssl_scanner.py
│   ├── vulnerability_scanner.py
│   ├── banner_grabber.py
│   ├── dns_scanner.py
│   └── brute_force.py
├── tests/               # Test suite
│   └── test_core.py
├── reports/             # Generated reports
└── wordlists/           # Brute force wordlists
```

---

## ⚠️ Legal Disclaimer

**Only scan systems you have explicit authorization to test.**

Unauthorized scanning is illegal and unethical in most jurisdictions.
All traffic is routed through Tor for your protection.
The authors assume no liability for misuse of this software.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0.1 | 2026-01-29 | Bug fixes, improved Tor detection, test suite |
| 3.0.0 | 2026-01-28 | Mandatory Tor, JSON+Markdown reports only |
| 2.0.0 | - | Added Tor support, HTML reports |
| 1.0.0 | - | Initial release |
