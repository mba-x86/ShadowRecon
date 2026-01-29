"""
Base Scanner Class
Provides common functionality for all security scanners
"""

import socket
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding"""
    title: str
    description: str
    severity: SeverityLevel
    category: str
    recommendation: str
    evidence: str = ""
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'category': self.category,
            'recommendation': self.recommendation,
            'evidence': self.evidence,
            'cvss_score': self.cvss_score,
            'cve_ids': self.cve_ids,
            'references': self.references
        }


@dataclass
class ScanResult:
    """Container for scan results"""
    scanner_name: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "pending"
    findings: List[Finding] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'scanner_name': self.scanner_name,
            'target': self.target,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'status': self.status,
            'findings': [f.to_dict() for f in self.findings],
            'raw_data': self.raw_data,
            'errors': self.errors,
            'summary': {
                'total_findings': len(self.findings),
                'critical': sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL),
                'high': sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH),
                'medium': sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM),
                'low': sum(1 for f in self.findings if f.severity == SeverityLevel.LOW),
                'info': sum(1 for f in self.findings if f.severity == SeverityLevel.INFO),
            }
        }


class BaseScanner(ABC):
    """Abstract base class for all security scanners"""
    
    def __init__(self, target: str, timeout: int = 10, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logging.getLogger(self.__class__.__name__)
        self.result: Optional[ScanResult] = None
        
    @abstractmethod
    def scan(self) -> ScanResult:
        """Execute the scan - must be implemented by subclasses"""
        pass
    
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return the name of the scanner"""
        pass
    
    def _init_result(self) -> ScanResult:
        """Initialize a new scan result"""
        return ScanResult(
            scanner_name=self.scanner_name,
            target=self.target,
            start_time=datetime.now()
        )
    
    def _finalize_result(self, result: ScanResult, status: str = "completed") -> ScanResult:
        """Finalize the scan result"""
        result.end_time = datetime.now()
        result.status = status
        return result
    
    def _add_finding(self, result: ScanResult, finding: Finding) -> None:
        """Add a finding to the result"""
        result.findings.append(finding)
        if self.verbose:
            self.logger.info(f"Finding: [{finding.severity.value}] {finding.title}")
    
    def _add_error(self, result: ScanResult, error: str) -> None:
        """Add an error to the result"""
        result.errors.append(error)
        self.logger.error(error)
    
    def _check_port(self, port: int, protocol: str = "tcp") -> bool:
        """Check if a port is open"""
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except Exception as e:
            self.logger.debug(f"Port check failed for {port}: {e}")
            return False
    
    def _grab_banner(self, port: int, send_data: bytes = b'') -> Optional[str]:
        """Attempt to grab a service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            if send_data:
                sock.send(send_data)
            
            banner = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except Exception as e:
            self.logger.debug(f"Banner grab failed for port {port}: {e}")
            return None
    
    def _resolve_hostname(self) -> Optional[str]:
        """Resolve target to IP address"""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None
    
    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None
    
    def log_progress(self, message: str) -> None:
        """Log progress message"""
        if self.verbose:
            self.logger.info(f"[{self.scanner_name}] {message}")
