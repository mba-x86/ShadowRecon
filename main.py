"""
ShadowRecon - Stealth Security Reconnaissance Framework
Main Entry Point - Orchestrates all security scans

Author: ShadowRecon Team
Purpose: Advanced server security assessment for SoftEther, WireGuard, and SSH

SECURITY: All scans are routed through Tor network - NO EXPOSED SCANS ALLOWED
DISCLAIMER: This tool is for authorized security testing only.
Only use on systems you have explicit permission to test.
"""

import argparse
import sys
import os
import logging
import re
from datetime import datetime
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from version import __version__

from scanners import (
    PortScanner,
    SSHScanner,
    SoftEtherScanner,
    WireGuardScanner,
    SSLScanner,
    VulnerabilityScanner,
    BannerGrabber,
    DNSScanner,
    BruteForceScanner
)
from scanners.base_scanner import ScanResult
from report_generator import ReportGenerator

# Try to import Tor manager
try:
    from tor_manager import TorManager, check_tor_installation, print_tor_status
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ''
    class Style:
        BRIGHT = RESET_ALL = ''


class PenTestToolkit:
    """
    Main Penetration Testing Toolkit
    Orchestrates all security scans and generates reports
    """
    
    BANNER = r"""
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗                     ║
    ║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║                     ║
    ║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║                     ║
    ║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║                     ║
    ║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝                     ║
    ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝                      ║
    ║                                                                           ║
    ║   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                             ║
    ║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                             ║
    ║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                             ║
    ║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                             ║
    ║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                             ║
    ║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                             ║
    ║                                                                           ║
    ║          🔮 Stealth Security Reconnaissance Framework v{version} 🔮             ║
    ║              🧅 ALL TRAFFIC ROUTED THROUGH TOR NETWORK 🧅                 ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
    """.format(version=__version__)
    
    def __init__(self, target: str, options: argparse.Namespace):
        self.target = target
        self.options = options
        self.scan_results: List[ScanResult] = []
        self.start_time = datetime.now()
        self.tor_manager = None
        self.using_tor = False
        self.target_dir = None  # Directory for this target's reports
        
        # Setup logging
        log_level = logging.DEBUG if options.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ShadowRecon')
    
    @property
    def effective_timeout(self) -> int:
        """Get timeout adjusted for Tor (3x longer for Tor connections)"""
        base_timeout = self.options.timeout
        if self.using_tor:
            return base_timeout * 3  # Tor adds significant latency
        return base_timeout
    
    def print_banner(self) -> None:
        """Print the toolkit banner"""
        if COLORS_AVAILABLE:
            print(Fore.CYAN + self.BANNER + Style.RESET_ALL)
        else:
            print(self.BANNER)
    
    def print_status(self, message: str, status: str = "info") -> None:
        """Print status message with color"""
        colors = {
            'info': Fore.BLUE,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.MAGENTA
        }
        
        symbols = {
            'info': '[*]',
            'success': '[+]',
            'warning': '[!]',
            'error': '[-]',
            'critical': '[!!]'
        }
        
        color = colors.get(status, Fore.WHITE)
        symbol = symbols.get(status, '[*]')
        
        if COLORS_AVAILABLE:
            print(f"{color}{Style.BRIGHT}{symbol}{Style.RESET_ALL} {message}")
        else:
            print(f"{symbol} {message}")
    
    def run_port_scan(self) -> Optional[ScanResult]:
        """Run port scanner"""
        self.print_status("Running Port Scanner...", "info")
        try:
            scanner = PortScanner(
                target=self.target,
                port_range=self.options.port_range,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            self.print_status(f"Port scan completed: {len(scanner.open_ports)} open ports found", "success")
            return result
        except Exception as e:
            self.print_status(f"Port scan failed: {e}", "error")
            return None
    
    def run_ssh_scan(self) -> Optional[ScanResult]:
        """Run SSH security scanner"""
        self.print_status("Running SSH Security Scanner...", "info")
        try:
            scanner = SSHScanner(
                target=self.target,
                port=self.options.ssh_port,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"SSH scan completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"SSH scan failed: {e}", "error")
            return None
    
    def run_softether_scan(self) -> Optional[ScanResult]:
        """Run SoftEther VPN scanner"""
        self.print_status("Running SoftEther VPN Scanner...", "info")
        try:
            scanner = SoftEtherScanner(
                target=self.target,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"SoftEther scan completed: {findings} findings", "success")
            return result
        except KeyboardInterrupt:
            raise  # Re-raise to be handled by run()
        except Exception as e:
            self.logger.debug(f"SoftEther scan exception: {e}")
            self.print_status(f"SoftEther scan failed: {e}", "error")
            return None
    
    def run_wireguard_scan(self) -> Optional[ScanResult]:
        """Run WireGuard VPN scanner"""
        self.print_status("Running WireGuard VPN Scanner...", "info")
        try:
            scanner = WireGuardScanner(
                target=self.target,
                port=self.options.wg_port,
                timeout=self.effective_timeout,
                verbose=self.options.verbose,
                config_path=self.options.wg_config
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"WireGuard scan completed: {findings} findings", "success")
            return result
        except KeyboardInterrupt:
            raise  # Re-raise to be handled by run()
        except Exception as e:
            self.logger.debug(f"WireGuard scan exception: {e}")
            self.print_status(f"WireGuard scan failed: {e}", "error")
            return None
    
    def run_ssl_scan(self) -> Optional[ScanResult]:
        """Run SSL/TLS scanner"""
        self.print_status("Running SSL/TLS Scanner...", "info")
        try:
            scanner = SSLScanner(
                target=self.target,
                port=443,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"SSL/TLS scan completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"SSL/TLS scan failed: {e}", "error")
            return None
    
    def run_vulnerability_scan(self) -> Optional[ScanResult]:
        """Run vulnerability scanner"""
        self.print_status("Running Vulnerability Scanner...", "info")
        try:
            scanner = VulnerabilityScanner(
                target=self.target,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"Vulnerability scan completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"Vulnerability scan failed: {e}", "error")
            return None
    
    def run_banner_grabbing(self) -> Optional[ScanResult]:
        """Run banner grabber"""
        self.print_status("Running Banner Grabber...", "info")
        try:
            scanner = BannerGrabber(
                target=self.target,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"Banner grabbing completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"Banner grabbing failed: {e}", "error")
            return None
    
    def run_dns_scan(self) -> Optional[ScanResult]:
        """Run DNS scanner"""
        self.print_status("Running DNS Scanner...", "info")
        try:
            scanner = DNSScanner(
                target=self.target,
                domain=self.options.domain,
                timeout=self.effective_timeout,
                verbose=self.options.verbose
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"DNS scan completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"DNS scan failed: {e}", "error")
            return None
    
    def run_brute_force_test(self) -> Optional[ScanResult]:
        """Run brute force tester (if enabled)"""
        if not self.options.brute_force:
            return None
        
        self.print_status("Running Brute Force Tester (AUTHORIZED USE ONLY)...", "warning")
        try:
            scanner = BruteForceScanner(
                target=self.target,
                service=self.options.brute_service,
                timeout=self.effective_timeout,
                verbose=self.options.verbose,
                max_attempts=self.options.brute_max_attempts
            )
            result = scanner.scan()
            findings = len(result.findings)
            self.print_status(f"Brute force test completed: {findings} findings", "success")
            return result
        except Exception as e:
            self.print_status(f"Brute force test failed: {e}", "error")
            return None
    
    def run_all_scans(self) -> List[ScanResult]:
        """Run all enabled scans with proper error handling"""
        results = []
        
        scan_methods = [
            ('port', self.run_port_scan),
            ('ssh', self.run_ssh_scan),
            ('softether', self.run_softether_scan),
            ('wireguard', self.run_wireguard_scan),
            ('ssl', self.run_ssl_scan),
            ('vulnerability', self.run_vulnerability_scan),
            ('banner', self.run_banner_grabbing),
            ('dns', self.run_dns_scan),
            ('brute', self.run_brute_force_test),
        ]
        
        for scan_name, scan_method in scan_methods:
            # Check if scan is enabled
            skip_option = getattr(self.options, f'skip_{scan_name}', False)
            if skip_option:
                self.print_status(f"Skipping {scan_name} scan", "info")
                continue
            
            try:
                result = scan_method()
                if result:
                    results.append(result)
            except KeyboardInterrupt:
                self.print_status(f"Scan interrupted during {scan_name}", "warning")
                raise
            except Exception as e:
                self.logger.exception(f"Unexpected error in {scan_name} scan")
                self.print_status(f"Error in {scan_name} scan: {e}", "error")
        
        return results
    
    def generate_reports(self) -> None:
        """Generate all report formats in target-specific folder"""
        if not self.scan_results:
            self.print_status("No scan results to report", "warning")
            return
        
        # Create target-specific directory: reports/<target>/<timestamp>/
        base_reports_dir = os.path.abspath(self.options.output_dir)
        target_safe = re.sub(r'[^\w\-.]', '_', self.target)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.target_dir = os.path.join(base_reports_dir, target_safe, timestamp)
        os.makedirs(self.target_dir, exist_ok=True)
        
        generator = ReportGenerator(
            self.target, 
            self.scan_results,
            tor_ip=self.tor_manager.tor_ip if self.tor_manager else None
        )
        
        # JSON Report
        json_path = os.path.join(self.target_dir, 'report.json')
        generator.generate_json_report(json_path)
        self.print_status(f"JSON report saved: {json_path}", "success")
        
        # Markdown Report
        md_path = os.path.join(self.target_dir, 'report.md')
        generator.generate_markdown_report(md_path)
        self.print_status(f"Markdown report saved: {md_path}", "success")
        
        # Print summary
        generator.print_summary()
    
    def setup_tor(self) -> bool:
        """Setup Tor connection for anonymous scanning - auto-starts if needed"""
        if not TOR_AVAILABLE:
            self.print_status("Tor manager not available - install PySocks and stem", "error")
            return False
        
        self.print_status("🧅 Setting up Tor network connection...", "info")
        
        # Initialize Tor manager with auto-start enabled
        self.tor_manager = TorManager(
            socks_port=self.options.tor_port,
            control_port=self.options.tor_control_port,
            auto_start=True,  # Auto-start Tor if not running
            auto_detect=(self.options.tor_port is None)
        )
        
        # Check if Tor is running, if not try to start it
        if not self.tor_manager._is_tor_running():
            self.print_status("🧅 Tor is not running, attempting to start...", "info")
            if self.tor_manager._start_tor():
                self.print_status("🧅 Tor started successfully!", "success")
            else:
                self.print_status("Failed to start Tor automatically", "error")
                self.print_status("Please start Tor manually:", "info")
                print("    Windows: Start Tor Browser or run tor.exe")
                print("    Linux:   sudo systemctl start tor")
                print("    Mac:     brew services start tor")
                return False
        
        # Connect to Tor
        if self.tor_manager.connect():
            self.using_tor = True
            status = self.tor_manager.get_status()
            self.print_status(f"🧅 Connected to Tor network!", "success")
            self.print_status(f"   Original IP: {status['original_ip']}", "info")
            self.print_status(f"   Tor IP: {status['current_ip']}", "info")
            return True
        else:
            self.print_status("Failed to connect to Tor network", "error")
            return False
    
    def disconnect_tor(self) -> None:
        """Disconnect from Tor network"""
        if self.tor_manager and self.using_tor:
            self.tor_manager.disconnect()
            self.print_status("🧅 Disconnected from Tor network", "info")
            self.using_tor = False
    
    def rotate_tor_ip(self) -> None:
        """Rotate Tor exit node for new IP"""
        if self.tor_manager and self.using_tor:
            self.print_status("🧅 Rotating Tor IP address...", "info")
            if self.tor_manager.rotate_ip():
                self.print_status(f"   New IP: {self.tor_manager.tor_ip}", "success")
            else:
                self.print_status("   IP rotation failed (may need Tor control port)", "warning")
    
    def run(self) -> int:
        """Main execution method"""
        self.print_banner()
        
        print()
        self.print_status(f"Target: {self.target}", "info")
        self.print_status(f"Started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", "info")
        print()
        
        # Disclaimer
        print("=" * 70)
        self.print_status("DISCLAIMER: This tool is for authorized security testing only!", "warning")
        self.print_status("Ensure you have explicit permission to test the target system.", "warning")
        print("=" * 70)
        print()
        
        # Tor is MANDATORY - no exposed scans allowed
        self.print_status("🧅 Tor connection is MANDATORY - No exposed scans allowed", "info")
        if not self.setup_tor():
            self.print_status("FATAL: Cannot proceed without Tor connection!", "critical")
            self.print_status("Please ensure Tor is running before using ShadowRecon.", "error")
            print()
            self.print_status("To start Tor:", "info")
            print("    Windows: Start Tor Browser or Tor Expert Bundle")
            print("    Linux:   sudo systemctl start tor")
            print("    Mac:     brew services start tor")
            return 3
        
        print()
        
        # Run scans
        try:
            self.scan_results = self.run_all_scans()
        except KeyboardInterrupt:
            self.print_status("Scan interrupted by user", "warning")
            self.disconnect_tor()
            return 130
        except Exception as e:
            self.print_status(f"Scan error: {e}", "error")
            self.logger.exception("Scan failed with exception")
            self.disconnect_tor()
            return 2
        
        # Calculate duration
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        print()
        self.print_status(f"All scans completed in {duration}", "success")
        print()
        
        # Generate reports
        self.generate_reports()
        
        # Disconnect from Tor
        self.disconnect_tor()
        
        # Return exit code based on findings
        if any(r.status == "failed" for r in self.scan_results):
            return 2  # Some scans failed
        
        critical_findings = sum(
            sum(1 for f in r.findings if f.severity.value == 'CRITICAL')
            for r in self.scan_results
        )
        
        if critical_findings > 0:
            return 1  # Critical findings found
        
        return 0  # Success


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f'ShadowRecon v{__version__} - Stealth Security Reconnaissance Framework (Tor-Mandatory)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py 192.168.1.1
  python main.py example.com --verbose
  python main.py 10.0.0.1 --skip-brute --output-dir ./reports
  python main.py 192.168.1.1 --ssh-port 2222 --wg-port 51821
  python main.py example.com --port-range vpn --skip-dns

IMPORTANT: All scans are routed through Tor network automatically.
           Tor must be running before using ShadowRecon.
           
To start Tor:
  Windows: Start Tor Browser or download Tor Expert Bundle
  Linux:   sudo systemctl start tor
  Mac:     brew services start tor

Scan Types:
  By default, all scans are enabled except brute force testing.
  Use --brute-force to enable password testing (requires authorization).
  Use --skip-* options to disable specific scans.

Report Formats:
  - JSON: Machine-readable format for automation
  - Markdown: Human-readable report with findings
        '''
    )
    
    # Required arguments (optional if --check-tor is used)
    parser.add_argument(
        'target',
        nargs='?',
        default=None,
        help='Target IP address or hostname to scan'
    )
    
    # General options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    # Tor configuration options (Tor is mandatory, but ports can be customized)
    parser.add_argument(
        '--tor-port',
        type=int,
        default=None,
        help='Tor SOCKS5 proxy port (auto-detected if not specified)'
    )
    
    parser.add_argument(
        '--tor-control-port',
        type=int,
        default=None,
        help='Tor control port for IP rotation (auto-detected if not specified)'
    )
    
    parser.add_argument(
        '--check-tor',
        action='store_true',
        help='Check Tor installation status and exit'
    )
    
    # Port scan options
    parser.add_argument(
        '--port-range',
        default='common',
        help='Port range to scan: common, vpn, all, or range like 1-1000 (default: common)'
    )
    
    # SSH options
    parser.add_argument(
        '--ssh-port',
        type=int,
        default=22,
        help='SSH port to scan (default: 22)'
    )
    
    # WireGuard options
    parser.add_argument(
        '--wg-port',
        type=int,
        default=51820,
        help='WireGuard port to scan (default: 51820)'
    )
    
    parser.add_argument(
        '--wg-config',
        help='Path to WireGuard config file for analysis'
    )
    
    # DNS options
    parser.add_argument(
        '--domain',
        help='Domain name for DNS scanning (default: target)'
    )
    
    # Brute force options
    parser.add_argument(
        '--brute-force',
        action='store_true',
        help='Enable brute force testing (AUTHORIZED USE ONLY)'
    )
    
    parser.add_argument(
        '--brute-service',
        default='ssh',
        choices=['ssh', 'ftp'],
        help='Service to test for brute force (default: ssh)'
    )
    
    parser.add_argument(
        '--brute-max-attempts',
        type=int,
        default=10,
        help='Maximum brute force attempts (default: 10)'
    )
    
    # Skip options
    parser.add_argument(
        '--skip-port',
        action='store_true',
        help='Skip port scanning'
    )
    
    parser.add_argument(
        '--skip-ssh',
        action='store_true',
        help='Skip SSH scanning'
    )
    
    parser.add_argument(
        '--skip-softether',
        action='store_true',
        help='Skip SoftEther scanning'
    )
    
    parser.add_argument(
        '--skip-wireguard',
        action='store_true',
        help='Skip WireGuard scanning'
    )
    
    parser.add_argument(
        '--skip-ssl',
        action='store_true',
        help='Skip SSL/TLS scanning'
    )
    
    parser.add_argument(
        '--skip-vulnerability',
        action='store_true',
        help='Skip vulnerability scanning'
    )
    
    parser.add_argument(
        '--skip-banner',
        action='store_true',
        help='Skip banner grabbing'
    )
    
    parser.add_argument(
        '--skip-dns',
        action='store_true',
        help='Skip DNS scanning'
    )
    
    parser.add_argument(
        '--skip-brute',
        action='store_true',
        default=True,
        help='Skip brute force testing (default: True)'
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point"""
    args = parse_arguments()
    
    # Handle --check-tor flag (doesn't require target)
    if args.check_tor:
        if TOR_AVAILABLE:
            print_tor_status()
        else:
            print("Tor manager not available. Install dependencies:")
            print("  pip install PySocks stem requests[socks]")
        return 0
    
    # Require target for all other operations
    if not args.target:
        print("Error: target is required")
        print("Usage: python main.py <target> [options]")
        print("       python main.py --check-tor")
        return 1
    
    # Override skip_brute if brute_force is explicitly enabled
    if args.brute_force:
        args.skip_brute = False
    
    toolkit = PenTestToolkit(args.target, args)
    return toolkit.run()


if __name__ == '__main__':
    sys.exit(main())
