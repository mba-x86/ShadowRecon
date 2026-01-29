"""
WireGuard VPN Security Scanner
Security assessment for WireGuard VPN configurations
"""

import socket
import struct
import hashlib
import os
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class WireGuardScanner(BaseScanner):
    """
    WireGuard VPN Security Scanner
    - Port availability checking
    - Handshake initiation probing
    - Configuration analysis
    - Key security assessment
    - Endpoint exposure analysis
    """
    
    # WireGuard default port
    DEFAULT_PORT = 51820
    
    # WireGuard message types
    MSG_HANDSHAKE_INIT = 1
    MSG_HANDSHAKE_RESP = 2
    MSG_COOKIE_REPLY = 3
    MSG_TRANSPORT_DATA = 4
    
    def __init__(self, target: str, port: int = 51820, timeout: int = 5,
                 verbose: bool = False, config_path: str = None,
                 port_range: str = None):
        super().__init__(target, timeout, verbose)
        self.port = port
        self.config_path = config_path
        self.port_range = port_range  # For scanning multiple potential WG ports
        self.detected_ports: List[int] = []
        
    @property
    def scanner_name(self) -> str:
        return "WireGuard VPN Scanner"
    
    def _check_wireguard_port(self, port: int) -> Dict:
        """Check if WireGuard is responding on a port"""
        result = {
            'open': False,
            'wireguard_response': False,
            'response_type': None,
            'timing': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Create a probe packet (invalid handshake initiation)
            # This should trigger a response or timing behavior
            probe = self._create_probe_packet()
            
            start_time = time.time()
            sock.sendto(probe, (self.target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                end_time = time.time()
                
                result['open'] = True
                result['timing'] = end_time - start_time
                
                # Analyze response
                if len(data) >= 4:
                    msg_type = struct.unpack('<I', data[:4])[0] & 0xFF
                    
                    if msg_type == self.MSG_COOKIE_REPLY:
                        result['wireguard_response'] = True
                        result['response_type'] = 'Cookie Reply'
                    elif msg_type == self.MSG_HANDSHAKE_RESP:
                        result['wireguard_response'] = True
                        result['response_type'] = 'Handshake Response'
                        
            except socket.timeout:
                # Timeout could mean:
                # 1. Port closed
                # 2. WireGuard silently dropping invalid packets (expected behavior)
                # 3. Firewall dropping packets
                
                # Try ICMP-based detection
                result['timeout'] = True
                result['open'] = self._probe_port_with_timing(port)
                
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"WireGuard probe failed on port {port}: {e}")
        
        return result
    
    def _create_probe_packet(self) -> bytes:
        """Create a WireGuard probe packet"""
        # Create an invalid but well-formed handshake initiation
        # This is designed to elicit a response without completing handshake
        
        # Message type (1 = handshake initiation)
        msg_type = struct.pack('<I', self.MSG_HANDSHAKE_INIT)
        
        # Sender index (random)
        sender_index = os.urandom(4)
        
        # Random data to fill the rest (invalid ephemeral key, etc.)
        padding = os.urandom(140 - 8)  # Handshake init is 148 bytes total with MAC
        
        return msg_type + sender_index + padding
    
    def _probe_port_with_timing(self, port: int) -> bool:
        """Use timing analysis to detect if port is open"""
        try:
            # Send multiple probes and analyze timing patterns
            timings = []
            
            for _ in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                
                start = time.time()
                sock.sendto(b'\x00' * 32, (self.target, port))
                
                try:
                    sock.recvfrom(1024)
                except socket.timeout:
                    pass
                
                end = time.time()
                timings.append(end - start)
                sock.close()
            
            # If consistent timeout, likely WireGuard silently dropping
            # (which is normal behavior for invalid packets)
            avg_timing = sum(timings) / len(timings)
            return avg_timing >= 0.4  # Near timeout suggests silent drop
            
        except Exception:
            return False
    
    def _scan_port_range(self) -> List[int]:
        """Scan a range of ports for WireGuard"""
        detected = []
        
        if self.port_range:
            start, end = map(int, self.port_range.split('-'))
            ports = range(start, end + 1)
        else:
            # Common WireGuard ports
            ports = [51820, 51821, 51822, 51823, 51824, 51825]
        
        for port in ports:
            result = self._check_wireguard_port(port)
            if result['open'] or result.get('wireguard_response'):
                detected.append(port)
                self.log_progress(f"Potential WireGuard on port {port}")
        
        return detected
    
    def _analyze_config_file(self, config_path: str) -> Dict:
        """Analyze a WireGuard configuration file for security issues"""
        issues = []
        config_data = {}
        
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            lines = content.split('\n')
            current_section = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('['):
                    current_section = line.strip('[]')
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if current_section:
                        if current_section not in config_data:
                            config_data[current_section] = {}
                        config_data[current_section][key] = value
            
            # Security checks
            interface = config_data.get('Interface', {})
            peers = [v for k, v in config_data.items() if k.startswith('Peer')]
            
            # Check private key exposure
            if 'PrivateKey' in interface:
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': 'Private key stored in configuration file',
                    'recommendation': 'Use wg genkey and store private key securely'
                })
            
            # Check for AllowedIPs = 0.0.0.0/0
            for peer in peers:
                if peer.get('AllowedIPs') == '0.0.0.0/0':
                    issues.append({
                        'severity': 'INFO',
                        'issue': 'Full tunnel mode enabled (all traffic through VPN)',
                        'recommendation': 'Verify this is intended - may cause issues with local network'
                    })
                
                # Check for missing PersistentKeepalive
                if 'PersistentKeepalive' not in peer:
                    issues.append({
                        'severity': 'LOW',
                        'issue': 'PersistentKeepalive not set',
                        'recommendation': 'Set PersistentKeepalive = 25 for NAT traversal'
                    })
            
            # Check DNS configuration
            if 'DNS' not in interface:
                issues.append({
                    'severity': 'LOW',
                    'issue': 'DNS not configured in WireGuard interface',
                    'recommendation': 'Configure DNS to prevent DNS leaks'
                })
            
            config_data['_issues'] = issues
            
        except FileNotFoundError:
            issues.append({
                'severity': 'ERROR',
                'issue': f'Configuration file not found: {config_path}',
                'recommendation': 'Provide valid configuration file path'
            })
        except Exception as e:
            issues.append({
                'severity': 'ERROR',
                'issue': f'Error parsing configuration: {e}',
                'recommendation': 'Check configuration file format'
            })
        
        return config_data
    
    def _check_key_security(self, public_key: str = None) -> Dict:
        """Analyze key security aspects"""
        result = {
            'recommendations': []
        }
        
        if public_key:
            # Basic key format validation
            if len(public_key) != 44:  # Base64 encoded 32 bytes
                result['key_format_valid'] = False
                result['recommendations'].append("Public key format appears invalid")
            else:
                result['key_format_valid'] = True
        
        # General recommendations
        result['recommendations'].extend([
            "Rotate keys periodically (every 90 days recommended)",
            "Store private keys with restricted permissions (chmod 600)",
            "Use different keys for different peers",
            "Never share private keys across multiple devices",
            "Implement key revocation procedure"
        ])
        
        return result
    
    def _check_endpoint_exposure(self) -> Dict:
        """Analyze endpoint exposure and potential risks"""
        result = {
            'endpoint': self.target,
            'port': self.port,
            'exposure_risks': []
        }
        
        # Check if endpoint is using well-known port
        if self.port == 51820:
            result['exposure_risks'].append({
                'risk': 'Default WireGuard port',
                'severity': 'LOW',
                'recommendation': 'Consider using non-standard port to reduce automated scanning'
            })
        
        # DNS resolution check
        try:
            ip = socket.gethostbyname(self.target)
            if ip != self.target:
                result['resolved_ip'] = ip
                result['uses_hostname'] = True
                result['exposure_risks'].append({
                    'risk': 'Endpoint uses hostname',
                    'severity': 'INFO',
                    'recommendation': 'Hostname resolution may leak DNS queries'
                })
        except:
            pass
        
        return result
    
    def scan(self) -> ScanResult:
        """Execute WireGuard security scan"""
        result = self._init_result()
        
        self.log_progress("Starting WireGuard VPN scan")
        
        # Check main WireGuard port
        main_port_result = self._check_wireguard_port(self.port)
        result.raw_data['main_port'] = {
            'port': self.port,
            **main_port_result
        }
        
        # Scan additional ports if requested
        if self.port_range:
            self.detected_ports = self._scan_port_range()
            result.raw_data['detected_ports'] = self.detected_ports
        else:
            if main_port_result['open'] or main_port_result.get('timeout'):
                self.detected_ports = [self.port]
        
        self.log_progress(f"Detected WireGuard ports: {self.detected_ports}")
        
        # Analyze configuration if provided
        if self.config_path:
            config_analysis = self._analyze_config_file(self.config_path)
            result.raw_data['config_analysis'] = config_analysis
            self.log_progress("Configuration file analyzed")
        
        # Key security check
        key_security = self._check_key_security()
        result.raw_data['key_security'] = key_security
        
        # Endpoint exposure analysis
        endpoint_analysis = self._check_endpoint_exposure()
        result.raw_data['endpoint_analysis'] = endpoint_analysis
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate security findings for WireGuard"""
        
        # WireGuard detected
        if self.detected_ports:
            self._add_finding(result, Finding(
                title="WireGuard VPN Detected",
                description=f"WireGuard VPN service detected on port(s): {self.detected_ports}",
                severity=SeverityLevel.INFO,
                category="VPN Detection",
                recommendation="Ensure WireGuard is properly configured with strong keys and appropriate access controls.",
                evidence=f"Detected ports: {self.detected_ports}"
            ))
        
        # Main port check
        main_port_info = result.raw_data.get('main_port', {})
        if main_port_info.get('wireguard_response'):
            self._add_finding(result, Finding(
                title="WireGuard Actively Responding",
                description="WireGuard is actively responding to probe packets.",
                severity=SeverityLevel.INFO,
                category="VPN Detection",
                recommendation="This is normal behavior. Ensure only authorized peers have access.",
                evidence=f"Response type: {main_port_info.get('response_type')}"
            ))
        
        # Default port warning
        endpoint_analysis = result.raw_data.get('endpoint_analysis', {})
        for risk in endpoint_analysis.get('exposure_risks', []):
            severity_map = {
                'CRITICAL': SeverityLevel.CRITICAL,
                'HIGH': SeverityLevel.HIGH,
                'MEDIUM': SeverityLevel.MEDIUM,
                'LOW': SeverityLevel.LOW,
                'INFO': SeverityLevel.INFO
            }
            self._add_finding(result, Finding(
                title=f"Endpoint Risk: {risk['risk']}",
                description=risk['risk'],
                severity=severity_map.get(risk['severity'], SeverityLevel.INFO),
                category="Endpoint Security",
                recommendation=risk['recommendation'],
                evidence=f"Endpoint: {self.target}:{self.port}"
            ))
        
        # Configuration file findings
        config_analysis = result.raw_data.get('config_analysis', {})
        for issue in config_analysis.get('_issues', []):
            severity_map = {
                'CRITICAL': SeverityLevel.CRITICAL,
                'HIGH': SeverityLevel.HIGH,
                'MEDIUM': SeverityLevel.MEDIUM,
                'LOW': SeverityLevel.LOW,
                'INFO': SeverityLevel.INFO,
                'ERROR': SeverityLevel.HIGH
            }
            self._add_finding(result, Finding(
                title=f"Configuration Issue: {issue['issue'][:50]}...",
                description=issue['issue'],
                severity=severity_map.get(issue['severity'], SeverityLevel.MEDIUM),
                category="Configuration Security",
                recommendation=issue['recommendation'],
                evidence=f"Config file: {self.config_path}"
            ))
        
        # Key security recommendations
        key_security = result.raw_data.get('key_security', {})
        for rec in key_security.get('recommendations', []):
            self._add_finding(result, Finding(
                title="Key Security Recommendation",
                description=rec,
                severity=SeverityLevel.INFO,
                category="Key Management",
                recommendation=rec,
                evidence="Best practice recommendation"
            ))
        
        # WireGuard-specific hardening
        self._add_finding(result, Finding(
            title="WireGuard Hardening Recommendations",
            description="Security best practices for WireGuard VPN",
            severity=SeverityLevel.INFO,
            category="Best Practices",
            recommendation="""
WireGuard Security Hardening Checklist:
1. Use strong, randomly generated keys (wg genkey)
2. Restrict AllowedIPs to minimum required ranges
3. Set PersistentKeepalive for NAT traversal
4. Configure DNS to prevent leaks
5. Use non-standard port if possible
6. Implement firewall rules to restrict source IPs
7. Enable and monitor WireGuard logs
8. Rotate keys periodically (every 90 days)
9. Use pre-shared keys for additional security
10. Store private keys with mode 600
11. Consider using wg-quick for managed configuration
12. Implement kill switch for clients
""",
            evidence="Hardening recommendations"
        ))
        
        # Pre-shared key recommendation
        self._add_finding(result, Finding(
            title="Pre-Shared Key (PSK) Recommendation",
            description="Consider using pre-shared keys for post-quantum security.",
            severity=SeverityLevel.LOW,
            category="Cryptography",
            recommendation="Add PresharedKey option to peer configuration for additional "
                           "symmetric encryption layer. This provides defense against future quantum computing threats.",
            evidence="Post-quantum security enhancement"
        ))
