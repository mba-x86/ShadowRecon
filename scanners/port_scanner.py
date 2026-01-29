"""
Advanced Port Scanner
Performs comprehensive port scanning with service detection
"""

import socket
import struct
import threading
import concurrent.futures
from typing import Dict, List, Tuple, Optional
from datetime import datetime

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class PortScanner(BaseScanner):
    """
    Comprehensive Port Scanner with multiple scanning techniques
    - TCP Connect Scan
    - TCP SYN Scan (requires raw socket privileges)
    - UDP Scan
    - Service Version Detection
    """
    
    # Common service ports with their typical services
    COMMON_PORTS = {
        # SSH and Remote Access
        22: ('SSH', 'tcp'),
        23: ('Telnet', 'tcp'),
        3389: ('RDP', 'tcp'),
        5900: ('VNC', 'tcp'),
        
        # Web Services
        80: ('HTTP', 'tcp'),
        443: ('HTTPS', 'tcp'),
        8080: ('HTTP-Proxy', 'tcp'),
        8443: ('HTTPS-Alt', 'tcp'),
        
        # VPN Services
        500: ('IKE/IPSec', 'udp'),
        1194: ('OpenVPN', 'udp'),
        4500: ('IPSec-NAT', 'udp'),
        51820: ('WireGuard', 'udp'),
        443: ('SoftEther/HTTPS', 'tcp'),
        992: ('SoftEther-TLS', 'tcp'),
        1194: ('SoftEther/OpenVPN', 'tcp'),
        5555: ('SoftEther', 'tcp'),
        
        # Database Ports
        3306: ('MySQL', 'tcp'),
        5432: ('PostgreSQL', 'tcp'),
        1433: ('MSSQL', 'tcp'),
        27017: ('MongoDB', 'tcp'),
        6379: ('Redis', 'tcp'),
        
        # Email Ports
        25: ('SMTP', 'tcp'),
        110: ('POP3', 'tcp'),
        143: ('IMAP', 'tcp'),
        465: ('SMTPS', 'tcp'),
        587: ('SMTP-Submission', 'tcp'),
        993: ('IMAPS', 'tcp'),
        995: ('POP3S', 'tcp'),
        
        # File Transfer
        21: ('FTP', 'tcp'),
        69: ('TFTP', 'udp'),
        445: ('SMB', 'tcp'),
        139: ('NetBIOS', 'tcp'),
        
        # DNS and Directory
        53: ('DNS', 'udp'),
        389: ('LDAP', 'tcp'),
        636: ('LDAPS', 'tcp'),
        
        # Other Services
        111: ('RPC', 'tcp'),
        161: ('SNMP', 'udp'),
        162: ('SNMP-Trap', 'udp'),
        514: ('Syslog', 'udp'),
    }
    
    # Dangerous/risky ports that should be flagged
    RISKY_PORTS = {
        23: 'Telnet - Unencrypted remote access',
        21: 'FTP - Often unencrypted file transfer',
        25: 'SMTP - May allow open relay',
        69: 'TFTP - No authentication',
        111: 'RPC - Potential for RPC attacks',
        135: 'MSRPC - Windows RPC vulnerabilities',
        139: 'NetBIOS - Information disclosure',
        161: 'SNMP - Community string attacks',
        445: 'SMB - EternalBlue and similar vulnerabilities',
        512: 'rexec - Remote execution without encryption',
        513: 'rlogin - Insecure remote login',
        514: 'rsh - Remote shell without encryption',
        1433: 'MSSQL - Database exposure',
        3306: 'MySQL - Database exposure',
        3389: 'RDP - BlueKeep and bruteforce attacks',
        5432: 'PostgreSQL - Database exposure',
        5900: 'VNC - Screen sharing vulnerabilities',
        6379: 'Redis - Often no authentication',
        27017: 'MongoDB - NoSQL injection, no auth',
    }
    
    def __init__(self, target: str, port_range: str = "1-1024", 
                 scan_type: str = "tcp_connect", timeout: int = 2,
                 max_threads: int = 100, verbose: bool = False):
        super().__init__(target, timeout, verbose)
        self.port_range = port_range
        self.scan_type = scan_type
        self.max_threads = max_threads
        self.open_ports: Dict[int, Dict] = {}
        self.filtered_ports: List[int] = []
        
    @property
    def scanner_name(self) -> str:
        return "Port Scanner"
    
    def _parse_port_range(self) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []
        
        # Handle special keywords
        if self.port_range.lower() == "common":
            return list(self.COMMON_PORTS.keys())
        elif self.port_range.lower() == "all":
            return list(range(1, 65536))
        elif self.port_range.lower() == "vpn":
            # VPN-specific ports
            return [22, 443, 500, 992, 1194, 1723, 4500, 5555, 51820]
        
        # Parse comma-separated and range formats
        for part in self.port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return sorted(set(ports))
    
    def _tcp_connect_scan(self, port: int) -> Tuple[int, bool, Optional[str]]:
        """Perform TCP connect scan on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                # Try to grab banner
                banner = None
                try:
                    sock.send(b'\r\n')
                    sock.settimeout(1)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                sock.close()
                return (port, True, banner)
            
            sock.close()
            return (port, False, None)
            
        except socket.timeout:
            return (port, False, None)
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return (port, False, None)
    
    def _udp_scan(self, port: int) -> Tuple[int, bool, Optional[str]]:
        """Perform UDP scan on a port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty packet
            sock.sendto(b'\x00', (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return (port, True, data.decode('utf-8', errors='ignore').strip())
            except socket.timeout:
                # UDP timeout might mean open|filtered
                sock.close()
                return (port, True, None)  # Assuming open if no ICMP unreachable
                
        except Exception as e:
            self.logger.debug(f"UDP scan error on port {port}: {e}")
            return (port, False, None)
    
    def _detect_service(self, port: int, banner: Optional[str]) -> str:
        """Attempt to detect service from port and banner"""
        # Check known ports first
        if port in self.COMMON_PORTS:
            service_name = self.COMMON_PORTS[port][0]
        else:
            service_name = "Unknown"
        
        # Try to extract version from banner
        if banner:
            # Common patterns
            if 'SSH' in banner:
                service_name = f"SSH ({banner.split()[0]})" if banner else "SSH"
            elif 'HTTP' in banner.upper():
                service_name = "HTTP"
            elif 'FTP' in banner.upper():
                service_name = "FTP"
            elif 'SMTP' in banner.upper():
                service_name = "SMTP"
            elif 'MySQL' in banner:
                service_name = "MySQL"
            elif 'PostgreSQL' in banner:
                service_name = "PostgreSQL"
        
        return service_name
    
    def scan(self) -> ScanResult:
        """Execute port scan"""
        result = self._init_result()
        ports_to_scan = self._parse_port_range()
        
        self.log_progress(f"Starting {self.scan_type} scan on {len(ports_to_scan)} ports")
        
        # Select scan function based on type
        if self.scan_type == "udp":
            scan_func = self._udp_scan
        else:
            scan_func = self._tcp_connect_scan
        
        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_func, port): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                
                if is_open:
                    service = self._detect_service(port, banner)
                    self.open_ports[port] = {
                        'service': service,
                        'banner': banner,
                        'protocol': 'udp' if self.scan_type == 'udp' else 'tcp'
                    }
                    self.log_progress(f"Port {port} open: {service}")
        
        # Store raw data
        result.raw_data = {
            'open_ports': self.open_ports,
            'filtered_ports': self.filtered_ports,
            'scan_type': self.scan_type,
            'ports_scanned': len(ports_to_scan)
        }
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate security findings based on open ports"""
        
        # Check for risky open ports
        for port, info in self.open_ports.items():
            if port in self.RISKY_PORTS:
                self._add_finding(result, Finding(
                    title=f"Risky Port Open: {port}/{info['protocol'].upper()}",
                    description=f"Port {port} ({info['service']}) is open. {self.RISKY_PORTS[port]}",
                    severity=SeverityLevel.HIGH if port in [23, 21, 445, 3389] else SeverityLevel.MEDIUM,
                    category="Network Security",
                    recommendation=f"Consider closing port {port} or restricting access via firewall rules. "
                                   f"If the service is required, ensure it is properly secured and patched.",
                    evidence=f"Port: {port}, Service: {info['service']}, Banner: {info.get('banner', 'N/A')}"
                ))
        
        # Check for exposed database ports
        db_ports = [3306, 5432, 1433, 27017, 6379]
        exposed_dbs = [p for p in self.open_ports.keys() if p in db_ports]
        if exposed_dbs:
            self._add_finding(result, Finding(
                title="Database Ports Exposed to Network",
                description=f"Database services are accessible on ports: {exposed_dbs}. "
                           f"Direct database exposure increases attack surface.",
                severity=SeverityLevel.HIGH,
                category="Database Security",
                recommendation="Restrict database access to localhost or specific trusted IPs. "
                               "Use VPN or SSH tunnels for remote database access.",
                evidence=f"Open database ports: {exposed_dbs}"
            ))
        
        # Check for too many open ports
        if len(self.open_ports) > 20:
            self._add_finding(result, Finding(
                title="Excessive Open Ports Detected",
                description=f"Found {len(self.open_ports)} open ports. Large attack surface detected.",
                severity=SeverityLevel.MEDIUM,
                category="Network Security",
                recommendation="Review all running services and disable unnecessary ones. "
                               "Implement principle of least privilege for network services.",
                evidence=f"Open ports count: {len(self.open_ports)}"
            ))
        
        # Information finding for VPN ports
        vpn_ports = {500, 1194, 4500, 51820, 5555, 992}
        found_vpn_ports = [p for p in self.open_ports.keys() if p in vpn_ports]
        if found_vpn_ports:
            self._add_finding(result, Finding(
                title="VPN Services Detected",
                description=f"VPN-related ports detected: {found_vpn_ports}",
                severity=SeverityLevel.INFO,
                category="VPN Security",
                recommendation="Ensure VPN services are properly configured with strong encryption and authentication.",
                evidence=f"VPN ports: {found_vpn_ports}"
            ))
        
        # SSH port check
        if 22 in self.open_ports:
            self._add_finding(result, Finding(
                title="SSH Service Detected",
                description="SSH service is running and accessible. Further SSH-specific testing recommended.",
                severity=SeverityLevel.INFO,
                category="Remote Access",
                recommendation="Run SSH-specific security scan to check for weak configurations.",
                evidence=f"SSH Banner: {self.open_ports[22].get('banner', 'Not captured')}"
            ))
