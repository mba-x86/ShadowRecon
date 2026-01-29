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
    
    def _verify_socks5_handshake(self, port: int) -> bool:
        """
        Verify that a real SOCKS5 proxy is running on the port
        by performing an actual SOCKS5 handshake.
        
        This prevents false positives from other services listening on the port.
        
        Returns:
            True if a valid SOCKS5 proxy responded correctly
        """
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(5)
            test_sock.connect((self.socks_host, port))
            
            # SOCKS5 greeting: version 5, 1 auth method (no auth)
            test_sock.send(b'\x05\x01\x00')
            
            # Expected response: version 5, accepted method 0 (no auth)
            response = test_sock.recv(2)
            test_sock.close()
            
            # Valid SOCKS5 response
            if response == b'\x05\x00':
                return True
            # SOCKS5 with different auth (still valid SOCKS5)
            elif len(response) == 2 and response[0:1] == b'\x05':
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"SOCKS5 handshake failed on port {port}: {e}")
            return False
    
    def _detect_tor_ports(self) -> Tuple[Optional[int], Optional[int]]:
        """
        Auto-detect which Tor instance is running using SOCKS5 handshake verification.
        
        Returns:
            Tuple of (socks_port, control_port) or (None, None) if not found
        """
        # Check Tor Browser ports first (more common for users)
        port_configs = [
            (self.TOR_BROWSER_SOCKS_PORT, self.TOR_BROWSER_CONTROL_PORT),  # Tor Browser
            (self.DEFAULT_SOCKS_PORT, self.DEFAULT_CONTROL_PORT),           # Standalone Tor
        ]
        
        for socks_port, control_port in port_configs:
            if self._verify_socks5_handshake(socks_port):
                self.logger.info(f"Detected Tor SOCKS5 proxy on port {socks_port}")
                return socks_port, control_port
        
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
        """
        Check if Tor is running and accepting SOCKS5 connections.
        Uses actual SOCKS5 handshake to verify, not just port check.
        """
        return self._verify_socks5_handshake(self.socks_port)
    
    def _find_tor_executable(self) -> Optional[str]:
        """Find Tor executable on the system"""
        system = platform.system().lower()
        
        if system == 'windows':
            # Common Tor installation paths on Windows
            tor_paths = [
                # Tor Browser (Desktop)
                os.path.expanduser(r'~\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'),
                # Tor Browser (OneDrive Desktop)
                os.path.expanduser(r'~\OneDrive\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'),
                # Tor Browser (Program Files)
                r'C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                r'C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe',
                # Tor Expert Bundle
                r'C:\Tor\tor.exe',
                r'C:\Program Files\Tor\tor.exe',
                r'C:\Program Files (x86)\Tor\tor.exe',
                os.path.expanduser(r'~\tor\tor.exe'),
                os.path.expanduser(r'~\Tor\tor.exe'),
                # Chocolatey install
                r'C:\ProgramData\chocolatey\lib\tor\tools\Tor\tor.exe',
            ]
            
            for path in tor_paths:
                if os.path.exists(path):
                    self.logger.debug(f"Found Tor at: {path}")
                    return path
            
            # Check if 'tor' is in PATH
            try:
                result = subprocess.run(['where', 'tor'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    path = result.stdout.strip().split('\n')[0]
                    self.logger.debug(f"Found Tor in PATH: {path}")
                    return path
            except Exception:
                pass
                
        else:
            # Linux/Mac
            tor_paths = [
                '/usr/bin/tor',
                '/usr/local/bin/tor',
                '/opt/homebrew/bin/tor',  # Mac M1/M2
                '/snap/bin/tor',
            ]
            
            for path in tor_paths:
                if os.path.exists(path):
                    self.logger.debug(f"Found Tor at: {path}")
                    return path
            
            # Check if 'tor' is in PATH
            try:
                result = subprocess.run(['which', 'tor'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    path = result.stdout.strip()
                    self.logger.debug(f"Found Tor in PATH: {path}")
                    return path
            except Exception:
                pass
        
        return None
    
    def _start_tor(self) -> bool:
        """Attempt to start Tor service"""
        system = platform.system().lower()
        
        try:
            if system == 'windows':
                tor_path = self._find_tor_executable()
                
                if tor_path:
                    self.logger.info(f"Starting Tor from: {tor_path}")
                    
                    # Start Tor as a background process
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                    
                    self.tor_process = subprocess.Popen(
                        [tor_path],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
                    )
                    
                    # Wait for Tor to bootstrap (up to 60 seconds)
                    print("    Waiting for Tor to bootstrap...", end='', flush=True)
                    for i in range(60):
                        time.sleep(1)
                        if self._is_tor_running():
                            print(" Done!")
                            self.logger.info("Tor started successfully")
                            # Update ports to standalone Tor
                            self.socks_port = self.DEFAULT_SOCKS_PORT
                            self.control_port = self.DEFAULT_CONTROL_PORT
                            return True
                        if i % 10 == 9:
                            print(".", end='', flush=True)
                    
                    print(" Timeout!")
                    self.logger.error("Tor failed to start within 60 seconds")
                    return False
                else:
                    self.logger.error("Tor executable not found")
                    return False
                    
            else:
                # Linux/Mac - try systemctl first
                try:
                    result = subprocess.run(['systemctl', 'start', 'tor'], 
                                   capture_output=True, timeout=10)
                    if result.returncode == 0:
                        print("    Waiting for Tor to start...", end='', flush=True)
                        for i in range(30):
                            time.sleep(1)
                            if self._is_tor_running():
                                print(" Done!")
                                self.logger.info("Tor started via systemctl")
                                return True
                        print(" Timeout!")
                except Exception:
                    pass
                
                # Try brew services on Mac
                if system == 'darwin':
                    try:
                        subprocess.run(['brew', 'services', 'start', 'tor'], 
                                       capture_output=True, timeout=10)
                        print("    Waiting for Tor to start...", end='', flush=True)
                        for i in range(30):
                            time.sleep(1)
                            if self._is_tor_running():
                                print(" Done!")
                                self.logger.info("Tor started via brew services")
                                return True
                        print(" Timeout!")
                    except Exception:
                        pass
                
                # Try direct tor command
                tor_path = self._find_tor_executable()
                if tor_path:
                    self.tor_process = subprocess.Popen(
                        [tor_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    print("    Waiting for Tor to bootstrap...", end='', flush=True)
                    for i in range(60):
                        time.sleep(1)
                        if self._is_tor_running():
                            print(" Done!")
                            self.logger.info("Tor started directly")
                            return True
                        if i % 10 == 9:
                            print(".", end='', flush=True)
                    print(" Timeout!")
            
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
        
        # Check if Tor is running (with SOCKS5 handshake verification)
        if not self._is_tor_running():
            self.logger.warning("Tor is not running (no valid SOCKS5 proxy detected)")
            
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
    
    def print_tor_status(self) -> None:
        """Print detailed Tor status for debugging"""
        print("\n=== Tor Status ===")
        
        # Check both port configurations
        for name, socks_port in [("Tor Browser", 9150), ("Standalone Tor", 9050)]:
            is_socks5 = self._verify_socks5_handshake(socks_port)
            status = "✓ SOCKS5 verified" if is_socks5 else "✗ Not running"
            print(f"  {name} (port {socks_port}): {status}")
        
        # Check for Tor executable
        tor_path = self._find_tor_executable()
        if tor_path:
            print(f"  Tor executable: {tor_path}")
        else:
            print("  Tor executable: Not found")
        
        print(f"  Current config: {self.socks_host}:{self.socks_port}")
        print(f"  Connected: {self.connected}")
        print("==================\n")
    
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
    import sys
    
    print("=" * 50)
    print("Tor Manager - Connection Test")
    print("=" * 50)
    
    # Create manager and print status
    tor = TorManager(auto_start=True)
    tor.print_tor_status()
    
    print("\nAttempting to connect to Tor...")
    
    if tor.connect():
        print(f"\n✓ Successfully connected to Tor!")
        print(f"  Original IP: {tor.original_ip}")
        print(f"  Tor IP:      {tor.tor_ip}")
        print(f"  SOCKS Port:  {tor.socks_port}")
        
        # Test IP rotation
        if STEM_AVAILABLE:
            print("\nAttempting IP rotation...")
            if tor.rotate_ip():
                print(f"  New IP: {tor.tor_ip}")
            else:
                print("  IP rotation failed (control port may require auth)")
        
        tor.disconnect()
        print("\n✓ Disconnected from Tor")
        sys.exit(0)
    else:
        print("\n✗ Failed to connect to Tor")
        print("\nTo use ShadowRecon, please ensure Tor is running:")
        print("  - Start Tor Browser, OR")
        print("  - Start Tor service: 'sudo systemctl start tor' (Linux)")
        print("  - Install Tor Expert Bundle and run tor.exe (Windows)")
        sys.exit(1)
