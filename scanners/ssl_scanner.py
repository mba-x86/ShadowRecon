"""
SSL/TLS Security Scanner
Comprehensive SSL/TLS configuration analysis
"""

import socket
import ssl
import hashlib
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class SSLScanner(BaseScanner):
    """
    SSL/TLS Security Scanner
    - Protocol version testing
    - Cipher suite analysis
    - Certificate validation
    - Known vulnerability checks (BEAST, POODLE, Heartbleed, etc.)
    """
    
    # Weak cipher patterns
    WEAK_CIPHERS = [
        'NULL', 'EXPORT', 'anon', 'DES', 'RC4', 'RC2', 'MD5',
        '3DES', 'IDEA', 'SEED', 'CAMELLIA'
    ]
    
    # Known vulnerable configurations
    VULNERABILITIES = {
        'sslv2': {'name': 'SSLv2 Support', 'severity': 'CRITICAL', 'cve': 'CVE-2016-0800'},
        'sslv3': {'name': 'SSLv3 POODLE', 'severity': 'HIGH', 'cve': 'CVE-2014-3566'},
        'tlsv1.0': {'name': 'TLSv1.0 Deprecated', 'severity': 'MEDIUM', 'cve': None},
        'tlsv1.1': {'name': 'TLSv1.1 Deprecated', 'severity': 'MEDIUM', 'cve': None},
        'heartbleed': {'name': 'Heartbleed', 'severity': 'CRITICAL', 'cve': 'CVE-2014-0160'},
        'ccs_injection': {'name': 'CCS Injection', 'severity': 'HIGH', 'cve': 'CVE-2014-0224'},
    }
    
    def __init__(self, target: str, port: int = 443, timeout: int = 10,
                 verbose: bool = False, check_all_protocols: bool = True):
        super().__init__(target, timeout, verbose)
        self.port = port
        self.check_all_protocols = check_all_protocols
        
    @property
    def scanner_name(self) -> str:
        return "SSL/TLS Scanner"
    
    def _test_protocol(self, protocol_version) -> Tuple[bool, Optional[str], Optional[Tuple]]:
        """Test if a specific SSL/TLS protocol version is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = protocol_version
            context.maximum_version = protocol_version
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            version = ssl_sock.version()
            cipher = ssl_sock.cipher()
            ssl_sock.close()
            
            return True, version, cipher
            
        except ssl.SSLError as e:
            return False, None, None
        except Exception as e:
            self.logger.debug(f"Protocol test failed: {e}")
            return False, None, None
    
    def _get_certificate_info(self) -> Optional[Dict]:
        """Retrieve and analyze server certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            cert_der = ssl_sock.getpeercert(binary_form=True)
            cert = ssl_sock.getpeercert()
            ssl_sock.close()
            
            if cert:
                # Parse certificate dates
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Calculate fingerprint
                fingerprint = hashlib.sha256(cert_der).hexdigest()
                
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': not_before.isoformat(),
                    'not_after': not_after.isoformat(),
                    'days_until_expiry': (not_after - datetime.now()).days,
                    'san': cert.get('subjectAltName', []),
                    'fingerprint_sha256': fingerprint,
                    'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown')
                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Certificate retrieval failed: {e}")
            return None
    
    def _get_supported_ciphers(self) -> List[Dict]:
        """Get list of supported cipher suites"""
        supported = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            
            # Get negotiated cipher
            current_cipher = ssl_sock.cipher()
            if current_cipher:
                supported.append({
                    'name': current_cipher[0],
                    'version': current_cipher[1],
                    'bits': current_cipher[2]
                })
            
            # Get shared ciphers
            shared = ssl_sock.shared_ciphers()
            if shared:
                for cipher in shared:
                    supported.append({
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    })
            
            ssl_sock.close()
            
        except Exception as e:
            self.logger.debug(f"Cipher enumeration failed: {e}")
        
        return supported
    
    def _analyze_cipher_strength(self, ciphers: List[Dict]) -> Dict:
        """Analyze cipher suite strength"""
        analysis = {
            'strong': [],
            'acceptable': [],
            'weak': [],
            'insecure': []
        }
        
        for cipher in ciphers:
            name = cipher['name']
            bits = cipher['bits']
            
            # Check for weak patterns
            is_weak = any(weak in name.upper() for weak in self.WEAK_CIPHERS)
            
            if is_weak or bits < 128:
                analysis['insecure'].append(cipher)
            elif bits < 256 or 'CBC' in name:
                analysis['weak'].append(cipher)
            elif 'GCM' in name or 'CHACHA20' in name:
                analysis['strong'].append(cipher)
            else:
                analysis['acceptable'].append(cipher)
        
        return analysis
    
    def _check_certificate_chain(self) -> Dict:
        """Check certificate chain validity"""
        result = {
            'chain_valid': False,
            'self_signed': False,
            'chain_length': 0,
            'issues': []
        }
        
        try:
            # Attempt to verify certificate with system trust store
            context = ssl.create_default_context()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            try:
                ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
                result['chain_valid'] = True
                ssl_sock.close()
            except ssl.SSLCertVerificationError as e:
                result['issues'].append(str(e))
                if 'self-signed' in str(e).lower():
                    result['self_signed'] = True
                sock.close()
                
        except Exception as e:
            result['issues'].append(str(e))
        
        return result
    
    def scan(self) -> ScanResult:
        """Execute SSL/TLS security scan"""
        result = self._init_result()
        
        self.log_progress(f"Starting SSL/TLS scan on port {self.port}")
        
        # Check if port is open
        if not self._check_port(self.port):
            self._add_error(result, f"Port {self.port} is not open")
            return self._finalize_result(result, "failed")
        
        # Test protocol versions
        protocols_tested = {}
        protocol_tests = [
            (ssl.TLSVersion.TLSv1_2, 'TLSv1.2'),
            (ssl.TLSVersion.TLSv1_3, 'TLSv1.3'),
        ]
        
        for proto_ver, proto_name in protocol_tests:
            supported, version, cipher = self._test_protocol(proto_ver)
            protocols_tested[proto_name] = {
                'supported': supported,
                'cipher': cipher[0] if cipher else None
            }
            self.log_progress(f"{proto_name}: {'Supported' if supported else 'Not supported'}")
        
        result.raw_data['protocols'] = protocols_tested
        
        # Get certificate information
        cert_info = self._get_certificate_info()
        if cert_info:
            result.raw_data['certificate'] = cert_info
            self.log_progress(f"Certificate valid until: {cert_info['not_after']}")
        
        # Get supported ciphers
        ciphers = self._get_supported_ciphers()
        cipher_analysis = self._analyze_cipher_strength(ciphers)
        result.raw_data['ciphers'] = ciphers
        result.raw_data['cipher_analysis'] = cipher_analysis
        
        # Check certificate chain
        chain_check = self._check_certificate_chain()
        result.raw_data['chain_verification'] = chain_check
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate security findings for SSL/TLS"""
        
        protocols = result.raw_data.get('protocols', {})
        cert_info = result.raw_data.get('certificate', {})
        cipher_analysis = result.raw_data.get('cipher_analysis', {})
        chain_check = result.raw_data.get('chain_verification', {})
        
        # Protocol findings
        if not protocols.get('TLSv1.3', {}).get('supported'):
            self._add_finding(result, Finding(
                title="TLS 1.3 Not Supported",
                description="Server does not support TLS 1.3, missing latest security features.",
                severity=SeverityLevel.LOW,
                category="SSL/TLS Protocol",
                recommendation="Enable TLS 1.3 for improved security and performance.",
                evidence=f"Supported protocols: {[k for k,v in protocols.items() if v.get('supported')]}"
            ))
        
        if not protocols.get('TLSv1.2', {}).get('supported'):
            self._add_finding(result, Finding(
                title="TLS 1.2 Not Supported",
                description="Server does not support TLS 1.2. This may cause compatibility issues.",
                severity=SeverityLevel.MEDIUM,
                category="SSL/TLS Protocol",
                recommendation="Enable TLS 1.2 as the minimum supported version.",
                evidence=f"Supported protocols: {[k for k,v in protocols.items() if v.get('supported')]}"
            ))
        
        # Certificate findings
        if cert_info:
            days_until_expiry = cert_info.get('days_until_expiry', 0)
            
            if days_until_expiry < 0:
                self._add_finding(result, Finding(
                    title="Certificate Expired",
                    description="The SSL/TLS certificate has expired!",
                    severity=SeverityLevel.CRITICAL,
                    category="Certificate",
                    recommendation="Renew the certificate immediately.",
                    evidence=f"Expired on: {cert_info['not_after']}"
                ))
            elif days_until_expiry < 30:
                self._add_finding(result, Finding(
                    title="Certificate Expiring Soon",
                    description=f"Certificate expires in {days_until_expiry} days.",
                    severity=SeverityLevel.HIGH,
                    category="Certificate",
                    recommendation="Renew the certificate before it expires.",
                    evidence=f"Expires on: {cert_info['not_after']}"
                ))
            elif days_until_expiry < 90:
                self._add_finding(result, Finding(
                    title="Certificate Expiring Within 90 Days",
                    description=f"Certificate expires in {days_until_expiry} days.",
                    severity=SeverityLevel.MEDIUM,
                    category="Certificate",
                    recommendation="Plan for certificate renewal.",
                    evidence=f"Expires on: {cert_info['not_after']}"
                ))
        
        # Chain verification findings
        if chain_check.get('self_signed'):
            self._add_finding(result, Finding(
                title="Self-Signed Certificate",
                description="Server is using a self-signed certificate.",
                severity=SeverityLevel.MEDIUM,
                category="Certificate",
                recommendation="Use a certificate from a trusted Certificate Authority.",
                evidence="Self-signed certificate detected"
            ))
        elif not chain_check.get('chain_valid'):
            self._add_finding(result, Finding(
                title="Certificate Chain Invalid",
                description="Certificate chain could not be validated.",
                severity=SeverityLevel.HIGH,
                category="Certificate",
                recommendation="Check certificate chain configuration and ensure intermediate certificates are installed.",
                evidence=f"Issues: {chain_check.get('issues', [])}"
            ))
        
        # Cipher findings
        if cipher_analysis.get('insecure'):
            self._add_finding(result, Finding(
                title="Insecure Ciphers Supported",
                description=f"Server supports insecure cipher suites: {[c['name'] for c in cipher_analysis['insecure']]}",
                severity=SeverityLevel.HIGH,
                category="Ciphers",
                recommendation="Disable all insecure ciphers (NULL, EXPORT, DES, RC4, etc.).",
                evidence=f"Insecure ciphers: {cipher_analysis['insecure']}"
            ))
        
        if cipher_analysis.get('weak'):
            self._add_finding(result, Finding(
                title="Weak Ciphers Supported",
                description=f"Server supports weak cipher suites: {[c['name'] for c in cipher_analysis['weak']]}",
                severity=SeverityLevel.MEDIUM,
                category="Ciphers",
                recommendation="Consider disabling weak ciphers and preferring GCM or ChaCha20 modes.",
                evidence=f"Weak ciphers: {cipher_analysis['weak']}"
            ))
        
        if cipher_analysis.get('strong'):
            self._add_finding(result, Finding(
                title="Strong Ciphers Available",
                description="Server supports strong cipher suites.",
                severity=SeverityLevel.INFO,
                category="Ciphers",
                recommendation="Ensure server prefers strong ciphers over weaker alternatives.",
                evidence=f"Strong ciphers: {[c['name'] for c in cipher_analysis['strong']]}"
            ))
