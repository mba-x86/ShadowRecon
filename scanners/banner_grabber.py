"""
Banner Grabber
Service identification through banner analysis
"""

import socket
import ssl
import re
from typing import Dict, List, Optional
from datetime import datetime

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class BannerGrabber(BaseScanner):
    """
    Banner Grabber and Service Identifier
    - TCP/UDP banner grabbing
    - Service fingerprinting
    - Version detection
    """
    
    # Service probes for different protocols
    SERVICE_PROBES = {
        'http': (b'GET / HTTP/1.0\r\nHost: {host}\r\n\r\n', 80),
        'https': (b'GET / HTTP/1.0\r\nHost: {host}\r\n\r\n', 443),
        'ssh': (b'', 22),
        'ftp': (b'', 21),
        'smtp': (b'EHLO test\r\n', 25),
        'pop3': (b'', 110),
        'imap': (b'', 143),
        'mysql': (b'', 3306),
        'postgres': (b'\x00\x00\x00\x08\x04\xd2\x16\x2f', 5432),
        'redis': (b'PING\r\n', 6379),
        'vnc': (b'', 5900),
        'rdp': (b'', 3389),
    }
    
    # Version extraction patterns
    VERSION_PATTERNS = {
        'ssh': r'SSH-[\d.]+-([\w.-]+)',
        'http': r'Server: ([^\r\n]+)',
        'ftp': r'220[- ]([^\r\n]+)',
        'smtp': r'220[- ]([^\r\n]+)',
        'mysql': r'(\d+\.\d+\.\d+)',
        'apache': r'Apache/([\d.]+)',
        'nginx': r'nginx/([\d.]+)',
        'openssh': r'OpenSSH[_-]([\d.p]+)',
    }
    
    def __init__(self, target: str, ports: List[int] = None, timeout: int = 5,
                 verbose: bool = False):
        super().__init__(target, timeout, verbose)
        self.ports = ports or [21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 
                               3306, 3389, 5432, 5900, 6379, 8080, 8443]
        
    @property
    def scanner_name(self) -> str:
        return "Banner Grabber"
    
    def _grab_tcp_banner(self, port: int, probe: bytes = b'') -> Optional[str]:
        """Grab banner from TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Replace placeholder in probe if present
            if b'{host}' in probe:
                probe = probe.replace(b'{host}', self.target.encode())
            
            if probe:
                sock.send(probe)
            
            # Try to receive banner
            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
            
        except Exception as e:
            self.logger.debug(f"TCP banner grab failed on port {port}: {e}")
            return None
    
    def _grab_ssl_banner(self, port: int, probe: bytes = b'') -> Optional[str]:
        """Grab banner from SSL/TLS port"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            
            if b'{host}' in probe:
                probe = probe.replace(b'{host}', self.target.encode())
            
            if probe:
                ssl_sock.send(probe)
            
            banner = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
            ssl_sock.close()
            
            return banner.strip() if banner else None
            
        except Exception as e:
            self.logger.debug(f"SSL banner grab failed on port {port}: {e}")
            return None
    
    def _identify_service(self, port: int, banner: str) -> Dict:
        """Identify service from banner"""
        result = {
            'service': 'unknown',
            'version': None,
            'product': None,
            'os_hint': None
        }
        
        if not banner:
            # Use port-based identification
            port_services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
                993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
                3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
                6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
            }
            result['service'] = port_services.get(port, f'Port-{port}')
            return result
        
        banner_lower = banner.lower()
        
        # SSH identification
        if banner.startswith('SSH-'):
            result['service'] = 'SSH'
            ssh_match = re.search(self.VERSION_PATTERNS['openssh'], banner)
            if ssh_match:
                result['version'] = ssh_match.group(1)
                result['product'] = 'OpenSSH'
        
        # HTTP identification
        elif 'http/' in banner_lower or 'server:' in banner_lower:
            result['service'] = 'HTTP'
            
            for product in ['nginx', 'apache', 'iis', 'lighttpd']:
                if product in banner_lower:
                    result['product'] = product.title()
                    version_match = re.search(rf'{product}/([\d.]+)', banner_lower)
                    if version_match:
                        result['version'] = version_match.group(1)
                    break
        
        # FTP identification
        elif banner.startswith('220'):
            result['service'] = 'FTP'
            if 'vsftpd' in banner_lower:
                result['product'] = 'vsFTPd'
            elif 'proftpd' in banner_lower:
                result['product'] = 'ProFTPD'
        
        # SMTP identification
        elif 'smtp' in banner_lower or 'esmtp' in banner_lower:
            result['service'] = 'SMTP'
            if 'postfix' in banner_lower:
                result['product'] = 'Postfix'
            elif 'exim' in banner_lower:
                result['product'] = 'Exim'
        
        # MySQL identification
        elif 'mysql' in banner_lower or port == 3306:
            result['service'] = 'MySQL'
            version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if version_match:
                result['version'] = version_match.group(1)
        
        # Redis identification
        elif '+pong' in banner_lower or 'redis' in banner_lower:
            result['service'] = 'Redis'
        
        # OS hints from banners
        if 'ubuntu' in banner_lower:
            result['os_hint'] = 'Ubuntu Linux'
        elif 'debian' in banner_lower:
            result['os_hint'] = 'Debian Linux'
        elif 'centos' in banner_lower or 'rhel' in banner_lower:
            result['os_hint'] = 'RHEL/CentOS'
        elif 'windows' in banner_lower:
            result['os_hint'] = 'Windows'
        
        return result
    
    def _analyze_banner_security(self, port: int, banner: str, service_info: Dict) -> List[Dict]:
        """Analyze banner for security issues"""
        issues = []
        
        if not banner:
            return issues
        
        banner_lower = banner.lower()
        
        # Check for version disclosure
        if service_info.get('version'):
            issues.append({
                'type': 'Version Disclosure',
                'severity': 'LOW',
                'description': f"Service version disclosed: {service_info.get('product', '')} {service_info.get('version')}"
            })
        
        # Check for OS disclosure
        if service_info.get('os_hint'):
            issues.append({
                'type': 'OS Information Disclosure',
                'severity': 'LOW',
                'description': f"Operating system hint: {service_info['os_hint']}"
            })
        
        # Check for debug/dev modes
        if any(word in banner_lower for word in ['debug', 'development', 'test']):
            issues.append({
                'type': 'Debug Mode Detected',
                'severity': 'MEDIUM',
                'description': 'Service appears to be in debug or development mode'
            })
        
        # Check for default configurations
        if 'default' in banner_lower:
            issues.append({
                'type': 'Default Configuration',
                'severity': 'MEDIUM',
                'description': 'Service may be using default configuration'
            })
        
        return issues
    
    def scan(self) -> ScanResult:
        """Execute banner grabbing scan"""
        result = self._init_result()
        
        self.log_progress(f"Starting banner grab on {len(self.ports)} ports")
        
        banners = {}
        
        for port in self.ports:
            # Check if port is open first
            if not self._check_port(port):
                continue
            
            self.log_progress(f"Grabbing banner from port {port}")
            
            # Try appropriate method based on port
            banner = None
            
            if port in [443, 993, 995, 8443, 992, 5555]:
                # Try SSL first for known SSL ports
                banner = self._grab_ssl_banner(port, b'GET / HTTP/1.0\r\n\r\n')
            
            if not banner:
                # Try TCP
                probe = b''
                for service, (service_probe, service_port) in self.SERVICE_PROBES.items():
                    if service_port == port:
                        probe = service_probe
                        break
                
                banner = self._grab_tcp_banner(port, probe)
            
            if banner:
                service_info = self._identify_service(port, banner)
                security_issues = self._analyze_banner_security(port, banner, service_info)
                
                banners[port] = {
                    'banner': banner[:500],  # Truncate long banners
                    'service_info': service_info,
                    'security_issues': security_issues
                }
                
                self.log_progress(f"Port {port}: {service_info.get('service')}")
        
        result.raw_data['banners'] = banners
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate findings from banner analysis"""
        
        banners = result.raw_data.get('banners', {})
        
        for port, info in banners.items():
            service_info = info.get('service_info', {})
            
            # Report each identified service
            self._add_finding(result, Finding(
                title=f"Service Identified: {service_info.get('service')} on Port {port}",
                description=f"Identified {service_info.get('service')} "
                           f"{'(' + service_info.get('product') + ')' if service_info.get('product') else ''} "
                           f"{'version ' + service_info.get('version') if service_info.get('version') else ''}",
                severity=SeverityLevel.INFO,
                category="Service Detection",
                recommendation="Ensure service is necessary and properly configured.",
                evidence=f"Banner: {info.get('banner', '')[:200]}"
            ))
            
            # Report security issues
            for issue in info.get('security_issues', []):
                severity_map = {
                    'HIGH': SeverityLevel.HIGH,
                    'MEDIUM': SeverityLevel.MEDIUM,
                    'LOW': SeverityLevel.LOW
                }
                self._add_finding(result, Finding(
                    title=f"{issue['type']} on Port {port}",
                    description=issue['description'],
                    severity=severity_map.get(issue['severity'], SeverityLevel.LOW),
                    category="Information Disclosure",
                    recommendation="Consider suppressing version and system information in service banners.",
                    evidence=f"Port {port}"
                ))
