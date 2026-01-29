# Server Penetration Testing Toolkit

## 🛡️ Overview

A comprehensive penetration testing toolkit designed for security assessment of VPN servers running **SoftEther**, **WireGuard**, and **SSH** services. This toolkit provides multiple scanning techniques and generates professional security reports.

## ⚠️ Disclaimer

**This tool is for authorized security testing only!**

Only use this toolkit on systems you have explicit permission to test. Unauthorized access to computer systems is illegal in most jurisdictions. The authors assume no liability for misuse of this software.

## 🚀 Features

### Scanners Included

| Scanner | Description |
|---------|-------------|
| **Port Scanner** | TCP/UDP port scanning with service detection |
| **SSH Scanner** | SSH protocol analysis, algorithm checking, vulnerability detection |
| **SoftEther Scanner** | SoftEther VPN detection, SSL/TLS analysis, admin interface checking |
| **WireGuard Scanner** | WireGuard detection, configuration analysis, key security checks |
| **SSL/TLS Scanner** | Protocol version testing, cipher analysis, certificate validation |
| **Vulnerability Scanner** | Known CVE checks, Heartbleed testing, misconfiguration detection |
| **Banner Grabber** | Service fingerprinting and version detection |
| **DNS Scanner** | Zone transfer testing, open resolver detection, DNSSEC checking |
| **Brute Force Scanner** | Password strength testing (optional, requires explicit enable) |

### Report Formats

- **HTML** - Professional formatted report with risk scores and charts
- **JSON** - Machine-readable format for automation and integration
- **TXT** - Plain text format for quick review

## 📋 Requirements

- Python 3.8+
- See `requirements.txt` for dependencies

## 🔧 Installation

```bash
# Clone or navigate to the toolkit directory
cd pentest_toolkit

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Basic Usage

```bash
# Scan a target with default settings
python main.py 192.168.1.1

# Scan with verbose output
python main.py example.com --verbose

# Scan specific IP with custom timeout
python main.py 10.0.0.1 --timeout 15
```

### Advanced Usage

```bash
# Full VPN-focused scan
python main.py 192.168.1.1 --port-range vpn --verbose

# Scan with custom SSH port
python main.py example.com --ssh-port 2222

# Scan with WireGuard config analysis
python main.py 10.0.0.1 --wg-port 51821 --wg-config /etc/wireguard/wg0.conf

# Skip specific scans
python main.py 192.168.1.1 --skip-dns --skip-banner

# Enable brute force testing (AUTHORIZED USE ONLY)
python main.py 192.168.1.1 --brute-force --brute-max-attempts 5
```

### 🧅 Anonymous Scanning with Tor

Route all scan traffic through the Tor network to hide your IP address:

```bash
# Check Tor installation status
python main.py --check-tor

# Scan through Tor network (requires Tor to be running)
python main.py 192.168.1.1 --use-tor

# Scan with Tor, but continue if Tor fails
python main.py example.com --use-tor --tor-optional

# Use custom Tor ports
python main.py 10.0.0.1 --use-tor --tor-port 9050 --tor-control-port 9051
```

**Tor Setup Requirements:**
- Install Tor: https://www.torproject.org/
- Start Tor service (default SOCKS5 port: 9050)
- For IP rotation, enable control port in torrc:
  ```
  ControlPort 9051
  CookieAuthentication 1
  ```
python main.py 192.168.1.1 --brute-force --brute-max-attempts 5
```

### All Options

```
usage: main.py [-h] [-v] [-t TIMEOUT] [-o OUTPUT_DIR] [--port-range PORT_RANGE]
               [--ssh-port SSH_PORT] [--wg-port WG_PORT] [--wg-config WG_CONFIG]
               [--domain DOMAIN] [--brute-force] [--brute-service {ssh,ftp}]
               [--brute-max-attempts BRUTE_MAX_ATTEMPTS] [--skip-port] [--skip-ssh]
               [--skip-softether] [--skip-wireguard] [--skip-ssl]
               [--skip-vulnerability] [--skip-banner] [--skip-dns] [--skip-brute]
               target

Options:
  target                Target IP address or hostname to scan
  -v, --verbose         Enable verbose output
  -t, --timeout         Connection timeout in seconds (default: 10)
  -o, --output-dir      Output directory for reports (default: ./reports)
  --port-range          Port range: common, vpn, all, or range like 1-1000
  --ssh-port            SSH port to scan (default: 22)
  --wg-port             WireGuard port (default: 51820)
  --wg-config           Path to WireGuard config file for analysis
  --domain              Domain name for DNS scanning
  --brute-force         Enable brute force testing (AUTHORIZED USE ONLY)
  --skip-*              Skip specific scan types
```

## 📊 Report Output

Reports are saved in the `reports/` directory with the following naming convention:
- `report_<target>_<timestamp>.html`
- `report_<target>_<timestamp>.json`
- `report_<target>_<timestamp>.txt`

### Risk Scoring

The toolkit calculates an overall risk score (0-100) based on findings:
- **CRITICAL** findings: 40 points each
- **HIGH** findings: 25 points each
- **MEDIUM** findings: 10 points each
- **LOW** findings: 3 points each
- **INFO** findings: 0 points

### Risk Levels

| Score | Level |
|-------|-------|
| 75-100 | CRITICAL |
| 50-74 | HIGH |
| 25-49 | MEDIUM |
| 1-24 | LOW |
| 0 | MINIMAL |

## 🔍 Scanner Details

### Port Scanner
- TCP Connect scanning
- Service detection
- Banner grabbing
- Risky port identification

### SSH Scanner
- Protocol version detection
- Key exchange algorithm analysis
- Cipher suite evaluation
- MAC algorithm checking
- Known CVE detection

### SoftEther Scanner
- Multi-port detection (443, 992, 1194, 5555, etc.)
- SSL/TLS configuration analysis
- Admin interface detection
- Protocol identification (L2TP, OpenVPN, SSTP)

### WireGuard Scanner
- UDP port probing
- Handshake detection
- Configuration file analysis
- Key security assessment
- Pre-shared key recommendations

### SSL/TLS Scanner
- TLS 1.2/1.3 support testing
- Certificate validation
- Cipher strength analysis
- Chain verification

### Vulnerability Scanner
- Heartbleed (CVE-2014-0160)
- Known SSH vulnerabilities
- Service exposure detection
- Misconfiguration checks

## 🛠️ Extending the Toolkit

### Adding a New Scanner

1. Create a new file in `scanners/` directory
2. Inherit from `BaseScanner` class
3. Implement the `scan()` method and `scanner_name` property
4. Add findings using `_add_finding()` method
5. Register in `scanners/__init__.py`

Example:
```python
from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel

class MyScanner(BaseScanner):
    @property
    def scanner_name(self) -> str:
        return "My Custom Scanner"
    
    def scan(self) -> ScanResult:
        result = self._init_result()
        # Your scanning logic here
        self._add_finding(result, Finding(
            title="Example Finding",
            description="Description of the issue",
            severity=SeverityLevel.MEDIUM,
            category="Custom Category",
            recommendation="How to fix"
        ))
        return self._finalize_result(result)
```

## 📝 License

This toolkit is provided for educational and authorized security testing purposes only.

## 👥 Contributing

Contributions are welcome! Please ensure any additions:
1. Follow the existing code style
2. Include proper documentation
3. Only add features for legitimate security testing

## 🔗 References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CVE Database](https://cve.mitre.org/)
- [SoftEther VPN](https://www.softether.org/)
- [WireGuard](https://www.wireguard.com/)
