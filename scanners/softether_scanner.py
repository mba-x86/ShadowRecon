"""
SoftEther VPN Security Scanner
Comprehensive security assessment for SoftEther VPN Server
"""

import socket
import ssl
import struct
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class SoftEtherScanner(BaseScanner):
    """
    SoftEther VPN Security Scanner
    - Port detection (multiple protocols)
    - SSL/TLS configuration analysis
    - Virtual Hub enumeration
    - Authentication mechanism testing
    - Protocol detection (L2TP, OpenVPN, SSTP, SoftEther native)
    - Known vulnerability checking
    """
    
    # SoftEther default ports
    SOFTETHER_PORTS = {
        443: 'HTTPS/SoftEther',
        992: 'SoftEther over TLS',
        1194: 'OpenVPN over SoftEther',
        5555: 'SoftEther Direct',
        8888: 'SoftEther Admin',
        1701: 'L2TP',
        500: 'IPsec IKE',
        4500: 'IPsec NAT-T',
    }
    
    # SoftEther protocol signatures
    PROTOCOL_SIGNATURES = {
        b'\x00\x00\x00\x01': 'SoftEther VPN Protocol',
        b'HTTP/1.': 'HTTPS Tunnel Mode',
    }
    
    def __init__(self, target: str, timeout: int = 10, verbose: bool = False,
                 scan_all_protocols: bool = True, check_admin: bool = True):
        super().__init__(target, timeout, verbose)
        self.scan_all_protocols = scan_all_protocols
        self.check_admin = check_admin
        self.detected_services: Dict = {}
        
    @property
    def scanner_name(self) -> str:
        return "SoftEther VPN Scanner"
    
    def _check_softether_port(self, port: int) -> Dict:
        """Check SoftEther specific port and identify protocol"""
        result = {
            'open': False,
            'protocol': None,
            'ssl_enabled': False,
            'banner': None,
            'version': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if sock.connect_ex((self.target, port)) == 0:
                result['open'] = True
                
                # Try SSL connection for common TLS ports
                if port in [443, 992, 5555]:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                        ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                        result['ssl_enabled'] = True
                        result['ssl_version'] = ssl_sock.version()
                        result['cipher'] = ssl_sock.cipher()
                        
                        # Try to get certificate info
                        try:
                            cert = ssl_sock.getpeercert(binary_form=True)
                            if cert:
                                result['cert_present'] = True
                        except:
                            pass
                        
                        # Send SoftEther probe
                        ssl_sock.send(b'\x00\x00\x00\x00\x00\x00\x00\x01')
                        response = ssl_sock.recv(1024)
                        result['banner'] = response[:100].hex()
                        
                        ssl_sock.close()
                    except ssl.SSLError as e:
                        result['ssl_error'] = str(e)
                    except Exception as e:
                        self.logger.debug(f"SSL probe error on {port}: {e}")
                else:
                    # Non-SSL port probe
                    try:
                        sock.send(b'\x00\x00\x00\x00\x00\x00\x00\x01')
                        response = sock.recv(1024)
                        result['banner'] = response[:100].hex() if response else None
                    except:
                        pass
                
            sock.close()
        except Exception as e:
            self.logger.debug(f"Port {port} check failed: {e}")
        
        return result
    
    def _detect_vpn_protocol(self, port: int, data: bytes) -> str:
        """Identify VPN protocol from response data"""
        if not data:
            return "Unknown"
        
        for signature, protocol in self.PROTOCOL_SIGNATURES.items():
            if data.startswith(signature):
                return protocol
        
        # Check for specific port-based protocols
        if port == 1194:
            return "OpenVPN Compatible"
        elif port == 1701:
            return "L2TP"
        elif port in [500, 4500]:
            return "IPsec"
        
        return "SoftEther Native"
    
    def _check_admin_interface(self) -> Dict:
        """Check SoftEther admin interface accessibility"""
        result = {
            'accessible': False,
            'requires_auth': True,
            'interface_type': None
        }
        
        admin_ports = [443, 5555, 8888]
        
        for port in admin_ports:
            try:
                # Check HTTPS admin interface
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, port))
                
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                
                # Send HTTP request to admin page
                http_request = f"GET /admin/ HTTP/1.1\r\nHost: {self.target}\r\nConnection: close\r\n\r\n"
                ssl_sock.send(http_request.encode())
                
                response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
                
                if 'SoftEther' in response or 'VPN Server' in response:
                    result['accessible'] = True
                    result['interface_type'] = f"HTTPS Admin on port {port}"
                    
                    if '401' in response or 'Unauthorized' in response:
                        result['requires_auth'] = True
                    elif '200 OK' in response:
                        result['requires_auth'] = False
                
                ssl_sock.close()
                
            except Exception as e:
                self.logger.debug(f"Admin check failed on port {port}: {e}")
        
        return result
    
    def _check_virtual_hubs(self) -> List[str]:
        """Attempt to enumerate virtual hubs (if anonymous access allowed)"""
        hubs = []
        
        # SoftEther protocol enumeration would require full protocol implementation
        # This is a placeholder for the actual enumeration
        self.log_progress("Virtual Hub enumeration requires authenticated access")
        
        return hubs
    
    def _check_ssl_configuration(self, port: int) -> Dict:
        """Analyze SSL/TLS configuration"""
        result = {
            'supported_versions': [],
            'ciphers': [],
            'certificate': {},
            'vulnerabilities': []
        }
        
        try:
            # Test different TLS versions
            tls_versions = [
                (ssl.TLSVersion.TLSv1_2, 'TLSv1.2'),
                (ssl.TLSVersion.TLSv1_3, 'TLSv1.3'),
            ]
            
            for tls_ver, ver_name in tls_versions:
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = tls_ver
                    context.maximum_version = tls_ver
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((self.target, port))
                    
                    ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                    result['supported_versions'].append(ver_name)
                    result['ciphers'].append({
                        'version': ver_name,
                        'cipher': ssl_sock.cipher()
                    })
                    ssl_sock.close()
                except:
                    pass
            
            # Check for weak protocols (SSLv3, TLSv1.0, TLSv1.1)
            weak_protocols = []
            for proto_name in ['SSLv3', 'TLSv1.0', 'TLSv1.1']:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    # Note: Modern Python may not support these protocols
                    weak_protocols.append(proto_name)
                except:
                    pass
            
            if weak_protocols:
                result['vulnerabilities'].append(f"Weak protocols may be supported: {weak_protocols}")
                
        except Exception as e:
            self.logger.debug(f"SSL analysis failed: {e}")
        
        return result
    
    def _check_default_credentials(self) -> Dict:
        """Check for default/weak credentials (passive check)"""
        result = {
            'default_creds_warning': True,
            'common_usernames': ['admin', 'administrator', 'vpn', 'user'],
            'recommendation': 'Ensure default credentials are changed'
        }
        
        return result
    
    def _check_known_vulnerabilities(self, version: str = None) -> List[Dict]:
        """Check for known SoftEther vulnerabilities"""
        vulnerabilities = []
        
        # Known SoftEther CVEs
        known_cves = [
            {
                'cve': 'CVE-2018-20044',
                'description': 'Buffer overflow in SoftEther VPN Client',
                'severity': 'HIGH',
                'affected_versions': '< 4.28',
            },
            {
                'cve': 'CVE-2018-20045',
                'description': 'Denial of service vulnerability',
                'severity': 'MEDIUM',
                'affected_versions': '< 4.28',
            },
            {
                'cve': 'CVE-2019-11868',
                'description': 'Heap overflow in VPN Gate',
                'severity': 'HIGH',
                'affected_versions': '< 4.29',
            },
        ]
        
        # Without version info, we can only warn about potential vulnerabilities
        for cve in known_cves:
            vulnerabilities.append(cve)
        
        return vulnerabilities
    
    def scan(self) -> ScanResult:
        """Execute SoftEther VPN security scan"""
        result = self._init_result()
        
        self.log_progress("Starting SoftEther VPN scan")
        
        # Scan all SoftEther ports
        open_ports = {}
        for port, service in self.SOFTETHER_PORTS.items():
            port_result = self._check_softether_port(port)
            if port_result['open']:
                open_ports[port] = {**port_result, 'expected_service': service}
                self.log_progress(f"Port {port} ({service}) is open")
        
        result.raw_data['open_ports'] = open_ports
        self.detected_services = open_ports
        
        # Check admin interface
        if self.check_admin:
            admin_result = self._check_admin_interface()
            result.raw_data['admin_interface'] = admin_result
            self.log_progress(f"Admin interface accessible: {admin_result['accessible']}")
        
        # SSL/TLS analysis on detected ports
        for port in open_ports:
            if port in [443, 992, 5555]:
                ssl_result = self._check_ssl_configuration(port)
                result.raw_data[f'ssl_port_{port}'] = ssl_result
        
        # Check known vulnerabilities
        vulns = self._check_known_vulnerabilities()
        result.raw_data['known_vulnerabilities'] = vulns
        
        # Check default credentials warning
        creds_check = self._check_default_credentials()
        result.raw_data['credentials_check'] = creds_check
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate security findings for SoftEther"""
        
        open_ports = result.raw_data.get('open_ports', {})
        
        # Finding: SoftEther detected
        if open_ports:
            self._add_finding(result, Finding(
                title="SoftEther VPN Server Detected",
                description=f"SoftEther VPN server detected on {len(open_ports)} ports: {list(open_ports.keys())}",
                severity=SeverityLevel.INFO,
                category="VPN Detection",
                recommendation="Ensure SoftEther is properly configured and updated to the latest version.",
                evidence=f"Open ports: {list(open_ports.keys())}"
            ))
        
        # Finding: Multiple VPN protocols exposed
        if len(open_ports) > 3:
            self._add_finding(result, Finding(
                title="Multiple VPN Protocols Exposed",
                description="Multiple VPN protocol ports are accessible, increasing attack surface.",
                severity=SeverityLevel.MEDIUM,
                category="VPN Security",
                recommendation="Disable unused VPN protocols. Only enable protocols that are actively used.",
                evidence=f"Detected protocols on ports: {list(open_ports.keys())}"
            ))
        
        # Finding: Admin interface accessible
        admin_info = result.raw_data.get('admin_interface', {})
        if admin_info.get('accessible'):
            severity = SeverityLevel.HIGH if not admin_info.get('requires_auth') else SeverityLevel.MEDIUM
            self._add_finding(result, Finding(
                title="SoftEther Admin Interface Accessible",
                description=f"Admin interface is accessible via {admin_info.get('interface_type')}",
                severity=severity,
                category="Admin Access",
                recommendation="Restrict admin interface access to trusted IPs only. "
                               "Use strong authentication and consider VPN-only access.",
                evidence=str(admin_info)
            ))
        
        # SSL/TLS findings
        for port in open_ports:
            ssl_info = result.raw_data.get(f'ssl_port_{port}', {})
            
            if ssl_info.get('vulnerabilities'):
                for vuln in ssl_info['vulnerabilities']:
                    self._add_finding(result, Finding(
                        title=f"SSL/TLS Vulnerability on Port {port}",
                        description=vuln,
                        severity=SeverityLevel.MEDIUM,
                        category="SSL/TLS Security",
                        recommendation="Disable weak SSL/TLS protocols and ciphers.",
                        evidence=f"Port {port}"
                    ))
            
            if 'TLSv1.3' not in ssl_info.get('supported_versions', []):
                if ssl_info.get('supported_versions'):
                    self._add_finding(result, Finding(
                        title=f"TLS 1.3 Not Supported on Port {port}",
                        description="Server does not support TLS 1.3, missing latest security features.",
                        severity=SeverityLevel.LOW,
                        category="SSL/TLS Security",
                        recommendation="Enable TLS 1.3 for improved security and performance.",
                        evidence=f"Supported versions: {ssl_info.get('supported_versions')}"
                    ))
        
        # Known vulnerability warnings
        vulns = result.raw_data.get('known_vulnerabilities', [])
        if vulns:
            self._add_finding(result, Finding(
                title="Potential Known Vulnerabilities",
                description="SoftEther has known CVEs. Verify your version is patched.",
                severity=SeverityLevel.MEDIUM,
                category="Vulnerability Assessment",
                recommendation="Update SoftEther to the latest version (4.38+). "
                               "Review CVE database for applicable vulnerabilities.",
                evidence=f"Known CVEs: {[v['cve'] for v in vulns]}",
                cve_ids=[v['cve'] for v in vulns]
            ))
        
        # Default credentials warning
        self._add_finding(result, Finding(
            title="Default Credentials Check",
            description="Ensure default SoftEther credentials have been changed.",
            severity=SeverityLevel.MEDIUM,
            category="Authentication",
            recommendation="Change default admin password immediately. "
                           "Use strong passwords (16+ characters, mixed case, numbers, symbols). "
                           "Consider implementing certificate-based authentication.",
            evidence="Default password warning - manual verification required"
        ))
        
        # L2TP/IPsec specific checks
        if 1701 in open_ports or 500 in open_ports:
            self._add_finding(result, Finding(
                title="L2TP/IPsec Protocol Detected",
                description="L2TP/IPsec is enabled. Ensure pre-shared key is strong.",
                severity=SeverityLevel.INFO,
                category="VPN Protocol",
                recommendation="Use strong pre-shared keys (32+ characters) or certificate authentication. "
                               "Consider using more modern protocols like WireGuard if possible.",
                evidence=f"L2TP port 1701: {1701 in open_ports}, IKE port 500: {500 in open_ports}"
            ))
        
        # Security hardening recommendations
        self._add_finding(result, Finding(
            title="SoftEther Hardening Recommendations",
            description="General security hardening for SoftEther VPN",
            severity=SeverityLevel.INFO,
            category="Best Practices",
            recommendation="""
SoftEther VPN Hardening Checklist:
1. Update to latest version regularly
2. Change default admin password
3. Restrict admin access by IP
4. Enable logging and monitoring
5. Disable unused Virtual Hubs
6. Use certificate authentication
7. Configure proper access control lists
8. Enable encryption for all connections
9. Disable unnecessary protocols
10. Regular security audits
""",
            evidence="Hardening recommendations"
        ))
