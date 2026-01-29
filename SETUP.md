# Pentest Toolkit - Setup Guide

A step-by-step guide to get the tool running.

---

## Prerequisites

- **Python 3.8+** installed
- **Nmap** installed and added to PATH (required for port scanning)
- **Git** (optional, for cloning)

---

## Step 1: Clone or Download

```bash
git clone https://github.com/YOUR_USERNAME/pentest_toolkit.git
cd pentest_toolkit
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

## Step 5: Configure (Optional)

Edit `config.yaml` to customize scan settings:

```yaml
general:
  timeout: 10        # Connection timeout
  verbose: false     # Enable detailed output
  max_threads: 100   # Concurrent threads

port_scanner:
  default_range: "common"  # common, vpn, all
```

---

## Step 6: Run the Tool

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

# Anonymous scan through Tor
python main.py 192.168.1.1 --use-tor
```

### Windows Batch File
```cmd
run_scan.bat
```

### Linux/Mac Shell Script
```bash
chmod +x run_scan.sh
./run_scan.sh
```

---

## Step 7: View Reports

Reports are saved in the `reports/` folder:
- **HTML** - Professional formatted report
- **JSON** - Machine-readable format
- **TXT** - Plain text summary

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
| `--use-tor` | Route through Tor network |
| `--skip-port` | Skip port scanning |
| `--skip-ssh` | Skip SSH scanning |
| `--skip-dns` | Skip DNS scanning |
| `--skip-ssl` | Skip SSL scanning |
| `--brute-force` | Enable brute force testing |

---

## Troubleshooting

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

---

## ⚠️ Legal Disclaimer

**Only scan systems you have explicit authorization to test.**

Unauthorized scanning is illegal and unethical.
