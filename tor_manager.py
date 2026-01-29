"""
Tor Network Manager
Provides anonymization through the Tor network for security scanning

Features:
- Automatic Tor connection management
- IP rotation (new identity)
- SOCKS5 proxy configuration
- Connection verification
"""

import socket
import socks
import time
import subprocess
import os
import platform
from typing import Optional, Tuple, Dict, Callable
from functools import wraps
import logging

# Try to import stem for Tor control
try:
    from stem import Signal
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

# Try to import requests for IP checking
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TorManager:
    """
    Manages Tor network connections for anonymous scanning
    
    Usage:
        tor = TorManager()
        tor.connect()
        
        # All socket connections now go through Tor
        # ... perform scans ...
        
        tor.rotate_ip()  # Get new identity
        tor.disconnect()
    """
    
    # Default Tor configuration
    DEFAULT_SOCKS_PORT = 9050
    DEFAULT_CONTROL_PORT = 9051
    DEFAULT_SOCKS_HOST = '127.0.0.1'
    
    # Tor Browser uses different ports
    TOR_BROWSER_SOCKS_PORT = 9150
    TOR_BROWSER_CONTROL_PORT = 9151
    
    # IP check services (onion-friendly)
    IP_CHECK_URLS = [
        'https://check.torproject.org/api/ip',
        'https://api.ipify.org?format=json',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
    ]
    
    def __init__(self, 
                 socks_port: int = None,
                 control_port: int = None,
                 socks_host: str = DEFAULT_SOCKS_HOST,
                 control_password: str = None,
                 auto_start: bool = False,
                 auto_detect: bool = True):
        """
        Initialize Tor Manager
        
        Args:
            socks_port: Tor SOCKS5 proxy port (auto-detected if None)
            control_port: Tor control port for identity rotation (auto-detected if None)
            socks_host: Tor SOCKS5 host (default: 127.0.0.1)
            control_password: Password for Tor control port (if set)
            auto_start: Automatically start Tor if not running
            auto_detect: Automatically detect Tor Browser vs standalone Tor ports
        """
        self.socks_host = socks_host
        self.control_password = control_password
        self.auto_start = auto_start
        self.logger = logging.getLogger('TorManager')
        
        self.connected = False
        self.original_socket = None
        self.tor_process = None
        self.original_ip = None
        self.tor_ip = None
        
        # Auto-detect which Tor instance is running
        if auto_detect and socks_port is None:
            detected_socks, detected_control = self._detect_tor_ports()
            self.socks_port = detected_socks or self.DEFAULT_SOCKS_PORT
            self.control_port = detected_control or self.DEFAULT_CONTROL_PORT
        else:
            self.socks_port = socks_port or self.DEFAULT_SOCKS_PORT
            self.control_port = control_port or self.DEFAULT_CONTROL_PORT
    
    def _detect_tor_ports(self) -> Tuple[Optional[int], Optional[int]]:
        """
        Auto-detect which Tor instance is running
        
        Returns:
            Tuple of (socks_port, control_port) or (None, None) if not found
        """
        # Check Tor Browser ports first (more common for users)
        port_configs = [
            (self.TOR_BROWSER_SOCKS_PORT, self.TOR_BROWSER_CONTROL_PORT),  # Tor Browser
            (self.DEFAULT_SOCKS_PORT, self.DEFAULT_CONTROL_PORT),           # Standalone Tor
        ]
        
        for socks_port, control_port in port_configs:
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(2)
                result = test_socket.connect_ex((self.socks_host, socks_port))
                test_socket.close()
                if result == 0:
                    self.logger.info(f"Detected Tor on port {socks_port}")
                    return socks_port, control_port
            except Exception:
                continue
        
        return None, None
    
    def _get_current_ip(self) -> Optional[str]:
        """Get current public IP address"""
        if not REQUESTS_AVAILABLE:
            return None
        
        for url in self.IP_CHECK_URLS:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    text = response.text.strip()
                    # Handle JSON response
                    if '{' in text:
                        import json
                        data = json.loads(text)
                        return data.get('IP') or data.get('ip') or data.get('origin')
                    return text
            except Exception as e:
                self.logger.debug(f"IP check failed for {url}: {e}")
                continue
        
        return None
    
    def _is_tor_running(self) -> bool:
        """Check if Tor is running and accepting connections"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            result = test_socket.connect_ex((self.socks_host, self.socks_port))
            test_socket.close()
            return result == 0
        except Exception:
            return False
    
    def _start_tor(self) -> bool:
        """Attempt to start Tor service"""
        system = platform.system().lower()
        
        try:
            if system == 'windows':
                # Try common Tor Browser paths on Windows
                tor_paths = [
                    r'C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                    r'C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                    os.path.expanduser(r'~\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'),
                    os.path.expanduser(r'~\OneDrive\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'),
                    # Tor Expert Bundle paths
                    r'C:\Tor\tor.exe',
                    r'C:\Program Files\Tor\tor.exe',
                    os.path.expanduser(r'~\tor\tor.exe'),
                    'tor',  # If in PATH (without .exe for compatibility)
                    'tor.exe',  # If in PATH
                ]
                
                for tor_path in tor_paths:
                    try:
                        # Check if path exists (skip for PATH-based commands)
                        if os.path.sep in tor_path and not os.path.exists(tor_path):
                            continue
                        
                        self.logger.info(f"Trying to start Tor from: {tor_path}")
                        self.tor_process = subprocess.Popen(
                            [tor_path],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                        )
                        # Wait for Tor to start (it needs time to bootstrap)
                        for _ in range(10):  # Try for up to 10 seconds
                            time.sleep(1)
                            if self._is_tor_running():
                                self.logger.info(f"Tor started successfully from {tor_path}")
                                return True
                    except FileNotFoundError:
                        continue
                    except Exception as e:
                        self.logger.debug(f"Failed to start Tor from {tor_path}: {e}")
                        continue
            else:
                # Linux/Mac - try systemctl or direct command
                try:
                    result = subprocess.run(['systemctl', 'start', 'tor'], 
                                   capture_output=True, timeout=10)
                    if result.returncode == 0:
                        time.sleep(3)
                        if self._is_tor_running():
                            self.logger.info("Tor started via systemctl")
                            return True
                except Exception:
                    pass
                
                # Try brew services on Mac
                if system == 'darwin':
                    try:
                        subprocess.run(['brew', 'services', 'start', 'tor'], 
                                       capture_output=True, timeout=10)
                        time.sleep(3)
                        if self._is_tor_running():
                            self.logger.info("Tor started via brew services")
                            return True
                    except Exception:
                        pass
                
                # Try direct tor command
                try:
                    self.tor_process = subprocess.Popen(
                        ['tor'],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    for _ in range(10):
                        time.sleep(1)
                        if self._is_tor_running():
                            self.logger.info("Tor started directly")
                            return True
                except Exception:
                    pass
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")
            return False
    
    def connect(self) -> bool:
        """
        Connect to Tor network and configure socket to use SOCKS5 proxy
        
        Returns:
            True if successfully connected to Tor
        """
        # Get original IP before connecting
        self.original_ip = self._get_current_ip()
        self.logger.info(f"Original IP: {self.original_ip}")
        
        # Check if Tor is running
        if not self._is_tor_running():
            self.logger.warning("Tor is not running")
            
            if self.auto_start:
                self.logger.info("Attempting to start Tor...")
                if not self._start_tor():
                    self.logger.error("Failed to start Tor automatically")
                    return False
            else:
                self.logger.error("Please start Tor manually or set auto_start=True")
                return False
        
        # Store original socket
        self.original_socket = socket.socket
        
        # Configure SOCKS5 proxy
        socks.set_default_proxy(socks.SOCKS5, self.socks_host, self.socks_port)
        socket.socket = socks.socksocket
        
        self.connected = True
        
        # Verify connection through Tor
        self.tor_ip = self._get_current_ip()
        
        if self.tor_ip and self.tor_ip != self.original_ip:
            self.logger.info(f"Connected to Tor! New IP: {self.tor_ip}")
            return True
        else:
            self.logger.warning("Connected to Tor but IP verification failed")
            return True  # Still connected, just couldn't verify
    
    def disconnect(self) -> None:
        """Disconnect from Tor and restore original socket"""
        if self.original_socket:
            socket.socket = self.original_socket
            self.original_socket = None
        
        # Reset SOCKS proxy
        socks.set_default_proxy()
        
        self.connected = False
        self.logger.info("Disconnected from Tor")
        
        # Stop Tor process if we started it
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except Exception:
                self.tor_process.kill()
            self.tor_process = None
    
    def rotate_ip(self) -> bool:
        """
        Request new Tor identity (new exit node = new IP)
        
        Returns:
            True if identity rotation was successful
        """
        if not STEM_AVAILABLE:
            self.logger.warning("stem library not available for IP rotation")
            return False
        
        try:
            with Controller.from_port(port=self.control_port) as controller:
                if self.control_password:
                    controller.authenticate(password=self.control_password)
                else:
                    controller.authenticate()
                
                # Request new identity
                controller.signal(Signal.NEWNYM)
                
                # Wait for new circuit
                time.sleep(5)
                
                # Verify new IP
                new_ip = self._get_current_ip()
                if new_ip and new_ip != self.tor_ip:
                    self.logger.info(f"IP rotated: {self.tor_ip} -> {new_ip}")
                    self.tor_ip = new_ip
                    return True
                else:
                    self.logger.warning("IP rotation requested but IP unchanged")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to rotate IP: {e}")
            return False
    
    def get_status(self) -> Dict:
        """Get current Tor connection status"""
        return {
            'connected': self.connected,
            'tor_running': self._is_tor_running(),
            'original_ip': self.original_ip,
            'current_ip': self.tor_ip or self._get_current_ip(),
            'socks_host': self.socks_host,
            'socks_port': self.socks_port,
        }
    
    def create_proxied_session(self) -> 'requests.Session':
        """Create a requests Session configured to use Tor"""
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests library not available")
        
        session = requests.Session()
        session.proxies = {
            'http': f'socks5h://{self.socks_host}:{self.socks_port}',
            'https': f'socks5h://{self.socks_host}:{self.socks_port}'
        }
        return session
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
        return False


class TorSocket:
    """
    Drop-in replacement for socket that routes through Tor
    
    Usage:
        with TorSocket() as sock:
            sock.connect(('example.com', 80))
            sock.send(b'GET / HTTP/1.0\r\n\r\n')
            response = sock.recv(4096)
    """
    
    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,
                 socks_host='127.0.0.1', socks_port=9050):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self._socket = socks.socksocket(family, type)
        self._socket.set_proxy(socks.SOCKS5, socks_host, socks_port)
    
    def connect(self, address: Tuple[str, int]) -> None:
        self._socket.connect(address)
    
    def send(self, data: bytes) -> int:
        return self._socket.send(data)
    
    def recv(self, bufsize: int) -> bytes:
        return self._socket.recv(bufsize)
    
    def settimeout(self, timeout: float) -> None:
        self._socket.settimeout(timeout)
    
    def close(self) -> None:
        self._socket.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def with_tor(func: Callable) -> Callable:
    """
    Decorator to run a function through Tor network
    
    Usage:
        @with_tor
        def my_scan_function(target):
            # This will run through Tor
            pass
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        tor = TorManager()
        try:
            if tor.connect():
                return func(*args, **kwargs)
            else:
                raise ConnectionError("Failed to connect to Tor")
        finally:
            tor.disconnect()
    
    return wrapper


def check_tor_installation() -> Dict:
    """
    Check Tor installation status and provide guidance
    
    Returns:
        Dictionary with installation status and instructions
    """
    result = {
        'installed': False,
        'running': False,
        'socks_port_open': False,
        'control_port_open': False,
        'socks_port': None,
        'control_port': None,
        'tor_browser': False,
        'instructions': []
    }
    
    system = platform.system().lower()
    
    # Check if Tor is in PATH
    try:
        subprocess.run(['tor', '--version'], capture_output=True, timeout=5)
        result['installed'] = True
    except Exception:
        pass
    
    # Check if Tor process is running (even if not in PATH)
    try:
        if system == 'windows':
            proc = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq tor.exe'], 
                                  capture_output=True, text=True, timeout=5)
            if 'tor.exe' in proc.stdout.lower():
                result['installed'] = True
        else:
            proc = subprocess.run(['pgrep', '-x', 'tor'], 
                                  capture_output=True, timeout=5)
            if proc.returncode == 0:
                result['installed'] = True
    except Exception:
        pass
    
    # Check SOCKS ports - Tor Browser (9150) first, then standard (9050)
    port_configs = [
        (9150, 9151, True),   # Tor Browser
        (9050, 9051, False),  # Standard Tor
    ]
    
    for socks_port, control_port, is_browser in port_configs:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if sock.connect_ex(('127.0.0.1', socks_port)) == 0:
                result['socks_port_open'] = True
                result['socks_port'] = socks_port
                result['running'] = True
                result['tor_browser'] = is_browser
                sock.close()
                
                # Check control port
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.settimeout(2)
                if sock2.connect_ex(('127.0.0.1', control_port)) == 0:
                    result['control_port_open'] = True
                    result['control_port'] = control_port
                sock2.close()
                break
            sock.close()
        except Exception:
            pass
    
    # Provide instructions based on status
    if not result['installed']:
        if system == 'windows':
            result['instructions'] = [
                "Tor is not installed. Installation options:",
                "1. Download Tor Browser from https://www.torproject.org/",
                "2. Or install via Chocolatey: choco install tor",
                "3. Or use the Expert Bundle from torproject.org"
            ]
        elif system == 'linux':
            result['instructions'] = [
                "Tor is not installed. Install with:",
                "Ubuntu/Debian: sudo apt install tor",
                "CentOS/RHEL: sudo yum install tor",
                "Arch: sudo pacman -S tor",
                "Then start: sudo systemctl start tor"
            ]
        elif system == 'darwin':
            result['instructions'] = [
                "Tor is not installed. Install with:",
                "brew install tor",
                "Then start: brew services start tor"
            ]
    elif not result['running']:
        if system == 'windows':
            result['instructions'] = [
                "Tor is installed but not running.",
                "Start Tor Browser or run tor.exe manually"
            ]
        else:
            result['instructions'] = [
                "Tor is installed but not running.",
                "Start with: sudo systemctl start tor",
                "Or: tor &"
            ]
    
    if not result['control_port_open'] and result['running']:
        result['instructions'].append(
            "Control port (9051) not accessible. For IP rotation, configure torrc with:"
        )
        result['instructions'].append("  ControlPort 9051")
        result['instructions'].append("  CookieAuthentication 1")
    
    return result


# Convenience function for quick Tor status check
def print_tor_status():
    """Print Tor installation and connection status"""
    status = check_tor_installation()
    
    print("\n" + "=" * 50)
    print("🧅 TOR STATUS CHECK")
    print("=" * 50)
    print(f"Installed: {'✅' if status['installed'] else '❌'}")
    print(f"Running: {'✅' if status['running'] else '❌'}")
    
    if status['running']:
        tor_type = "Tor Browser" if status['tor_browser'] else "Standalone Tor"
        print(f"Type: {tor_type}")
        print(f"SOCKS Port ({status['socks_port']}): ✅")
        print(f"Control Port ({status['control_port']}): {'✅' if status['control_port_open'] else '❌'}")
    else:
        print(f"SOCKS Port: ❌")
        print(f"Control Port: ❌")
    
    if status['instructions']:
        print("\n📋 Instructions:")
        for instruction in status['instructions']:
            print(f"  {instruction}")
    elif status['running']:
        print("\n✅ Tor is ready! Use --use-tor to anonymize your scans.")
    
    print("=" * 50 + "\n")
    
    return status


if __name__ == '__main__':
    # Run status check when executed directly
    print_tor_status()
