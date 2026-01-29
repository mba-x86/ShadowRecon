"""
Brute Force Testing Module
For testing password strength (use only on authorized systems)
"""

import socket
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Generator
from datetime import datetime
import threading
from queue import Queue

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class BruteForceScanner(BaseScanner):
    """
    Brute Force Testing Scanner
    - SSH brute force testing
    - VPN authentication testing
    - Rate limiting detection
    - Account lockout detection
    
    WARNING: Only use on systems you are authorized to test!
    """
    
    # Common weak passwords for testing
    COMMON_PASSWORDS = [
        'password', 'password123', '123456', '12345678', 'admin', 'root',
        'letmein', 'welcome', 'monkey', 'dragon', 'master', 'qwerty',
        '111111', 'abc123', 'password1', 'iloveyou', 'sunshine', 'princess',
        'admin123', 'root123', 'administrator', 'changeme', 'test', 'guest',
        'vpn', 'vpnpassword', 'softether', 'wireguard', 'server', 'linux'
    ]
    
    # Common usernames
    COMMON_USERNAMES = [
        'root', 'admin', 'administrator', 'user', 'test', 'guest',
        'vpn', 'server', 'operator', 'manager', 'sysadmin', 'webmaster',
        'ftpuser', 'backup', 'oracle', 'postgres', 'mysql', 'ubuntu',
        'centos', 'deploy', 'www-data', 'nobody'
    ]
    
    def __init__(self, target: str, service: str = 'ssh', port: int = None,
                 timeout: int = 10, verbose: bool = False, 
                 max_attempts: int = 10, delay: float = 1.0,
                 username_list: List[str] = None, password_list: List[str] = None):
        super().__init__(target, timeout, verbose)
        self.service = service.lower()
        self.port = port or self._get_default_port()
        self.max_attempts = max_attempts
        self.delay = delay
        self.username_list = username_list or self.COMMON_USERNAMES[:5]
        self.password_list = password_list or self.COMMON_PASSWORDS[:10]
        self.successful_credentials: List[Tuple[str, str]] = []
        self.rate_limited = False
        self.lockout_detected = False
        
    @property
    def scanner_name(self) -> str:
        return "Brute Force Scanner"
    
    def _get_default_port(self) -> int:
        """Get default port for service"""
        ports = {
            'ssh': 22,
            'ftp': 21,
            'telnet': 23,
            'rdp': 3389,
            'vnc': 5900,
            'mysql': 3306,
            'postgres': 5432,
            'http': 80,
            'https': 443,
        }
        return ports.get(self.service, 22)
    
    def _test_ssh_auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Test SSH authentication"""
        try:
            # Using raw socket for basic auth testing
            # In production, use paramiko for proper SSH testing
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send our version
            sock.send(b'SSH-2.0-BruteTest\r\n')
            
            # For actual testing, you'd need to implement full SSH handshake
            # or use paramiko library
            
            sock.close()
            
            # This is a placeholder - real implementation would use paramiko
            return False, "SSH auth testing requires paramiko library"
            
        except socket.timeout:
            return False, "Connection timeout"
        except Exception as e:
            return False, str(e)
    
    def _test_ftp_auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Test FTP authentication"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            
            # Receive banner
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if not response.startswith('220'):
                sock.close()
                return False, "Invalid FTP banner"
            
            # Send USER command
            sock.send(f'USER {username}\r\n'.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if response.startswith('331'):
                # Password required
                sock.send(f'PASS {password}\r\n'.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if response.startswith('230'):
                    sock.close()
                    return True, "Login successful"
                elif '530' in response:
                    sock.close()
                    return False, "Login failed"
            
            sock.close()
            return False, "Unexpected response"
            
        except Exception as e:
            return False, str(e)
    
    def _check_rate_limiting(self) -> Dict:
        """Check if target implements rate limiting"""
        result = {
            'rate_limiting': False,
            'lockout': False,
            'attempts_before_limit': 0
        }
        
        attempts = 0
        start_time = time.time()
        
        for _ in range(20):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                connect_result = sock.connect_ex((self.target, self.port))
                sock.close()
                
                if connect_result != 0:
                    result['rate_limiting'] = True
                    result['attempts_before_limit'] = attempts
                    break
                
                attempts += 1
                
            except Exception:
                result['rate_limiting'] = True
                result['attempts_before_limit'] = attempts
                break
        
        return result
    
    def _generate_credential_pairs(self) -> Generator[Tuple[str, str], None, None]:
        """Generate username/password pairs for testing"""
        attempt_count = 0
        
        for username in self.username_list:
            for password in self.password_list:
                if attempt_count >= self.max_attempts:
                    return
                yield username, password
                attempt_count += 1
    
    def _test_authentication(self, username: str, password: str) -> Tuple[bool, str]:
        """Test authentication based on service type"""
        if self.service == 'ssh':
            return self._test_ssh_auth(username, password)
        elif self.service == 'ftp':
            return self._test_ftp_auth(username, password)
        else:
            return False, f"Service {self.service} not implemented"
    
    def scan(self) -> ScanResult:
        """Execute brute force security test"""
        result = self._init_result()
        
        self.log_progress(f"Starting brute force test on {self.service}:{self.port}")
        self.log_progress("WARNING: Only use on authorized systems!")
        
        # Check if port is open
        if not self._check_port(self.port):
            self._add_error(result, f"Port {self.port} is not open")
            return self._finalize_result(result, "failed")
        
        # Check for rate limiting
        rate_limit_check = self._check_rate_limiting()
        result.raw_data['rate_limiting'] = rate_limit_check
        self.log_progress(f"Rate limiting: {'Detected' if rate_limit_check['rate_limiting'] else 'Not detected'}")
        
        # Test authentication (limited attempts)
        test_results = []
        for username, password in self._generate_credential_pairs():
            if self.rate_limited:
                self.log_progress("Rate limiting detected, stopping test")
                break
            
            success, message = self._test_authentication(username, password)
            test_results.append({
                'username': username,
                'password': '****',  # Don't log actual passwords
                'success': success,
                'message': message
            })
            
            if success:
                self.successful_credentials.append((username, password))
                self.log_progress(f"FOUND: {username}:****")
            
            time.sleep(self.delay)
        
        result.raw_data['test_results'] = test_results
        result.raw_data['successful_logins'] = len(self.successful_credentials)
        result.raw_data['attempts_made'] = len(test_results)
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate security findings from brute force test"""
        
        rate_limiting = result.raw_data.get('rate_limiting', {})
        
        # Successful credentials found
        if self.successful_credentials:
            self._add_finding(result, Finding(
                title="Weak Credentials Found",
                description=f"Found {len(self.successful_credentials)} account(s) with weak/common credentials.",
                severity=SeverityLevel.CRITICAL,
                category="Authentication",
                recommendation="Change passwords immediately to strong, unique values. "
                               "Implement password policies requiring minimum length, complexity, and regular rotation.",
                evidence=f"Accounts with weak passwords: {[c[0] for c in self.successful_credentials]}"
            ))
        
        # Rate limiting findings
        if not rate_limiting.get('rate_limiting'):
            self._add_finding(result, Finding(
                title="No Rate Limiting Detected",
                description="Service does not appear to implement rate limiting for authentication attempts.",
                severity=SeverityLevel.HIGH,
                category="Authentication",
                recommendation="Implement rate limiting (e.g., fail2ban, account lockout). "
                               "Configure maximum login attempts before temporary lockout.",
                evidence=f"Made {rate_limiting.get('attempts_before_limit', 20)}+ connections without being blocked"
            ))
        else:
            self._add_finding(result, Finding(
                title="Rate Limiting Detected",
                description=f"Rate limiting kicks in after approximately {rate_limiting.get('attempts_before_limit')} attempts.",
                severity=SeverityLevel.INFO,
                category="Authentication",
                recommendation="Rate limiting is implemented. Consider if threshold is appropriate.",
                evidence=f"Blocked after {rate_limiting.get('attempts_before_limit')} attempts"
            ))
        
        # Brute force recommendations
        self._add_finding(result, Finding(
            title="Brute Force Protection Recommendations",
            description="General recommendations for brute force protection",
            severity=SeverityLevel.INFO,
            category="Best Practices",
            recommendation="""
Brute Force Protection Checklist:
1. Install and configure fail2ban or similar
2. Implement account lockout after N failed attempts
3. Use strong password policies (min 12 chars, complexity)
4. Enable 2FA/MFA where possible
5. Consider certificate-based authentication
6. Monitor and alert on failed login attempts
7. Use CAPTCHA for web-based authentication
8. Implement progressive delays between attempts
9. Disable root/admin direct login
10. Use non-standard ports where appropriate
""",
            evidence="Security recommendations"
        ))
