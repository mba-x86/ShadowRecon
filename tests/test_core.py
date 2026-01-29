"""
ShadowRecon Test Suite
Basic tests for core functionality
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVersion:
    """Test version module"""
    
    def test_version_exists(self):
        from version import __version__
        assert __version__ is not None
        assert isinstance(__version__, str)
    
    def test_version_format(self):
        from version import __version__
        parts = __version__.split('.')
        assert len(parts) >= 2
        assert all(p.isdigit() for p in parts)
    
    def test_version_info(self):
        from version import __version_info__
        assert isinstance(__version_info__, tuple)
        assert len(__version_info__) >= 2


class TestTorManager:
    """Test Tor manager functionality"""
    
    def test_import(self):
        from tor_manager import TorManager
        assert TorManager is not None
    
    def test_verify_socks5_port_function(self):
        from tor_manager import _verify_socks5_port
        # Should return False for non-existent port
        result = _verify_socks5_port('127.0.0.1', 59999)
        assert result == False
    
    def test_check_tor_installation(self):
        from tor_manager import check_tor_installation
        result = check_tor_installation()
        assert isinstance(result, dict)
        assert 'installed' in result
        assert 'running' in result
        assert 'socks_port' in result
        assert 'instructions' in result
    
    def test_tor_manager_init(self):
        from tor_manager import TorManager
        tor = TorManager(auto_start=False, auto_detect=False)
        assert tor.socks_port == 9050
        assert tor.control_port == 9051
        assert tor.connected == False


class TestBaseScanner:
    """Test base scanner functionality"""
    
    def test_severity_levels(self):
        from scanners.base_scanner import SeverityLevel
        assert SeverityLevel.CRITICAL.value == 'CRITICAL'
        assert SeverityLevel.HIGH.value == 'HIGH'
        assert SeverityLevel.MEDIUM.value == 'MEDIUM'
        assert SeverityLevel.LOW.value == 'LOW'
        assert SeverityLevel.INFO.value == 'INFO'
    
    def test_finding_creation(self):
        from scanners.base_scanner import Finding, SeverityLevel
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=SeverityLevel.HIGH,
            category="Test",
            recommendation="Test recommendation"
        )
        assert finding.title == "Test Finding"
        assert finding.severity == SeverityLevel.HIGH
    
    def test_finding_to_dict(self):
        from scanners.base_scanner import Finding, SeverityLevel
        finding = Finding(
            title="Test",
            description="Desc",
            severity=SeverityLevel.MEDIUM,
            category="Cat",
            recommendation="Rec"
        )
        d = finding.to_dict()
        assert d['title'] == "Test"
        assert d['severity'] == "MEDIUM"
    
    def test_scan_result_creation(self):
        from scanners.base_scanner import ScanResult
        from datetime import datetime
        result = ScanResult(
            scanner_name="TestScanner",
            target="127.0.0.1",
            start_time=datetime.now()
        )
        assert result.scanner_name == "TestScanner"
        assert result.target == "127.0.0.1"
        assert result.status == "pending"
        assert result.findings == []


class TestReportGenerator:
    """Test report generator functionality"""
    
    def test_import(self):
        from report_generator import ReportGenerator
        assert ReportGenerator is not None
    
    def test_risk_calculation(self):
        from report_generator import ReportGenerator
        from scanners.base_scanner import ScanResult, Finding, SeverityLevel
        from datetime import datetime
        
        # Create a result with findings
        result = ScanResult(
            scanner_name="Test",
            target="127.0.0.1",
            start_time=datetime.now()
        )
        result.findings = [
            Finding(
                title="Critical",
                description="Desc",
                severity=SeverityLevel.CRITICAL,
                category="Test",
                recommendation="Fix"
            )
        ]
        
        gen = ReportGenerator("127.0.0.1", [result])
        risk = gen._calculate_risk_score()
        
        assert risk['score'] >= 40  # One critical = 40 points
        assert risk['level'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'MINIMAL']


class TestScannerImports:
    """Test that all scanners can be imported"""
    
    def test_port_scanner_import(self):
        from scanners import PortScanner
        assert PortScanner is not None
    
    def test_ssh_scanner_import(self):
        from scanners import SSHScanner
        assert SSHScanner is not None
    
    def test_softether_scanner_import(self):
        from scanners import SoftEtherScanner
        assert SoftEtherScanner is not None
    
    def test_wireguard_scanner_import(self):
        from scanners import WireGuardScanner
        assert WireGuardScanner is not None
    
    def test_ssl_scanner_import(self):
        from scanners import SSLScanner
        assert SSLScanner is not None
    
    def test_vulnerability_scanner_import(self):
        from scanners import VulnerabilityScanner
        assert VulnerabilityScanner is not None
    
    def test_banner_grabber_import(self):
        from scanners import BannerGrabber
        assert BannerGrabber is not None
    
    def test_dns_scanner_import(self):
        from scanners import DNSScanner
        assert DNSScanner is not None
    
    def test_brute_force_scanner_import(self):
        from scanners import BruteForceScanner
        assert BruteForceScanner is not None


class TestCLI:
    """Test CLI argument parsing"""
    
    def test_parse_arguments_import(self):
        from main import parse_arguments
        assert parse_arguments is not None
    
    def test_main_import(self):
        from main import main, PenTestToolkit
        assert main is not None
        assert PenTestToolkit is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
