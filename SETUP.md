# 🔮 ShadowRecon v3.0 - Setup Guide

A step-by-step guide to get ShadowRecon running.

> ⚠️ **IMPORTANT**: All scans are routed through Tor network. Tor must be running before using ShadowRecon.

---

## Prerequisites

- **Python 3.8+** installed
- **Nmap** installed and added to PATH (required for port scanning)
- **Tor** installed and running (MANDATORY for all scans)
- **Git** (optional, for cloning)

---

## Step 1: Clone or Download

```bash
git clone https://github.com/YOUR_USERNAME/shadowrecon.git
cd shadowrecon
```

Or download and extract the ZIP file.

---

## Step 2: Create Virtual Environment (Recommended)

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
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

---

## Step 4: Install Nmap

**Windows:**
- Download from https://nmap.org/download.html
- Run the installer
- Ensure "Add to PATH" is selected

**Linux:**
```bash
sudo apt install nmap        # Debian/Ubuntu
sudo yum install nmap        # CentOS/RHEL
```

**Mac:**
```bash
brew install nmap
```

Verify installation:
```bash
nmap --version
```

---

## Step 5: Install and Start Tor (MANDATORY)

### Windows
**Option 1: Tor Browser (Easiest)**
1. Download from https://www.torproject.org/download/
2. Install and launch Tor Browser
3. Keep it running while using ShadowRecon

**Option 2: Tor Expert Bundle**
1. Download Expert Bundle from https://www.torproject.org/download/tor/
2. Extract and run `tor.exe`

### Linux
```bash
sudo apt install tor         # Debian/Ubuntu
sudo yum install tor         # CentOS/RHEL

# Start Tor service
sudo systemctl start tor
sudo systemctl enable tor    # Auto-start on boot
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

---

## Step 6: Configure (Optional)

Edit `config.yaml` to customize scan settings:

```yaml
general:
  timeout: 10        # Connection timeout (Tor adds ~3x latency)
  verbose: false     # Enable detailed output
  max_threads: 100   # Concurrent threads

port_scanner:
  default_range: "common"  # common, vpn, all
```

---

## Step 7: Run the Tool

> 🧅 **Tor is mandatory** - ShadowRecon will not run without an active Tor connection.

### Basic Scan
```bash
python main.py <target>
```

**Examples:**
```bash
# Scan an IP address
python main.py 192.168.1.1

# Scan a domain with verbose output
python main.py example.com --verbose

# Scan VPN ports only
python main.py 192.168.1.1 --port-range vpn

# Skip DNS scanning
python main.py 192.168.1.1 --skip-dns

# Custom SSH port
python main.py 192.168.1.1 --ssh-port 2222

# Check Tor status
python main.py --check-tor
```

### Windows Batch File
```cmd
run_scan.bat <target>
```

### Linux/Mac Shell Script
```bash
chmod +x run_scan.sh
./run_scan.sh <target>
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

## Quick Reference

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Detailed output |
| `-t, --timeout` | Connection timeout (seconds) |
| `-o, --output-dir` | Report output directory |
| `--port-range` | `common`, `vpn`, `all`, or `1-1000` |
| `--ssh-port` | SSH port (default: 22) |
| `--wg-port` | WireGuard port (default: 51820) |
| `--tor-port` | Custom Tor SOCKS port (auto-detected) |
| `--check-tor` | Check Tor installation status |
| `--skip-port` | Skip port scanning |
| `--skip-ssh` | Skip SSH scanning |
| `--skip-dns` | Skip DNS scanning |
| `--skip-ssl` | Skip SSL scanning |
| `--brute-force` | Enable brute force testing |

---

## Troubleshooting

### "FATAL: Cannot proceed without Tor connection"
1. Ensure Tor is installed and running
2. Check with `python main.py --check-tor`
3. If using Tor Browser, make sure it's open
4. Try specifying the port: `--tor-port 9150` (Tor Browser) or `--tor-port 9050` (Standalone Tor)

### "nmap not found"
- Install Nmap and add to system PATH
- Restart terminal after installation

### Permission denied (Linux)
```bash
sudo python main.py <target>
```

### Module not found
```bash
pip install -r requirements.txt
```

### Slow scans
- Tor adds latency (3x timeout is applied automatically)
- Use `--skip-*` options to disable unnecessary scans
- Use `--port-range vpn` for faster VPN-focused scans

---

## ⚠️ Legal Disclaimer

**Only scan systems you have explicit authorization to test.**

Unauthorized scanning is illegal and unethical.
All traffic is routed through Tor for your protection.
