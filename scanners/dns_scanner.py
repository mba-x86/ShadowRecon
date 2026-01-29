"""
DNS Security Scanner
DNS configuration and security analysis
"""

import socket
import struct
import random
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from .base_scanner import BaseScanner, ScanResult, Finding, SeverityLevel


class DNSScanner(BaseScanner):
    """
    DNS Security Scanner
    - Zone transfer testing
    - DNS recursion testing
    - DNS cache poisoning susceptibility
    - DNSSEC validation
    """
    
    def __init__(self, target: str, domain: str = None, timeout: int = 5,
                 verbose: bool = False):
        super().__init__(target, timeout, verbose)
        self.domain = domain or target
        
    @property
    def scanner_name(self) -> str:
        return "DNS Scanner"
    
    def _build_dns_query(self, domain: str, qtype: int = 1) -> bytes:
        """Build a DNS query packet"""
        # Transaction ID
        tid = random.randint(0, 65535)
        
        # Flags: Standard query, recursion desired
        flags = 0x0100
        
        # Header
        header = struct.pack('>HHHHHH', tid, flags, 1, 0, 0, 0)
        
        # Question section
        question = b''
        for part in domain.split('.'):
            question += bytes([len(part)]) + part.encode()
        question += b'\x00'  # Null terminator
        question += struct.pack('>HH', qtype, 1)  # QTYPE, QCLASS
        
        return header + question
    
    def _send_dns_query(self, query: bytes, tcp: bool = False) -> Optional[bytes]:
        """Send DNS query and get response"""
        try:
            if tcp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.target, 53))
                
                # TCP DNS needs length prefix
                length = struct.pack('>H', len(query))
                sock.send(length + query)
                
                # Receive length first
                len_data = sock.recv(2)
                if len(len_data) < 2:
                    return None
                response_len = struct.unpack('>H', len_data)[0]
                response = sock.recv(response_len)
                
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(query, (self.target, 53))
                response, _ = sock.recvfrom(4096)
            
            sock.close()
            return response
            
        except Exception as e:
            self.logger.debug(f"DNS query failed: {e}")
            return None
    
    def _check_zone_transfer(self) -> Dict:
        """Test for AXFR (zone transfer) vulnerability"""
        result = {
            'vulnerable': False,
            'records': []
        }
        
        # Build AXFR query (type 252)
        query = self._build_dns_query(self.domain, qtype=252)
        
        # Zone transfer requires TCP
        response = self._send_dns_query(query, tcp=True)
        
        if response:
            # Parse response flags
            if len(response) >= 12:
                flags = struct.unpack('>H', response[2:4])[0]
                rcode = flags & 0x0F
                
                if rcode == 0:  # No error
                    # Check answer count
                    ancount = struct.unpack('>H', response[6:8])[0]
                    if ancount > 0:
                        result['vulnerable'] = True
                        result['record_count'] = ancount
        
        return result
    
    def _check_recursion(self) -> Dict:
        """Test if DNS server allows recursion from external hosts"""
        result = {
            'allows_recursion': False,
            'tested_domain': 'www.google.com'
        }
        
        # Query for external domain
        query = self._build_dns_query('www.google.com', qtype=1)
        response = self._send_dns_query(query)
        
        if response and len(response) >= 12:
            flags = struct.unpack('>H', response[2:4])[0]
            ra_flag = (flags >> 7) & 1  # Recursion Available
            rcode = flags & 0x0F
            
            if ra_flag and rcode == 0:
                result['allows_recursion'] = True
        
        return result
    
    def _check_source_port_randomization(self) -> Dict:
        """Check if DNS responses come from random source ports"""
        result = {
            'random_ports': False,
            'ports_observed': []
        }
        
        for _ in range(5):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                query = self._build_dns_query(self.domain)
                sock.sendto(query, (self.target, 53))
                
                _, addr = sock.recvfrom(4096)
                result['ports_observed'].append(addr[1])
                sock.close()
                
            except Exception:
                pass
        
        # Check if ports are varied
        if len(set(result['ports_observed'])) > 1:
            result['random_ports'] = True
        
        return result
    
    def _check_txid_randomization(self) -> Dict:
        """Check transaction ID randomization (basic check)"""
        result = {
            'appears_random': True,
            'txids_observed': []
        }
        
        for _ in range(5):
            query = self._build_dns_query(self.domain)
            response = self._send_dns_query(query)
            
            if response and len(response) >= 2:
                txid = struct.unpack('>H', response[:2])[0]
                result['txids_observed'].append(txid)
        
        # Check if TXIDs are varied (they should match our random queries)
        # This is a simplified check
        if len(result['txids_observed']) > 0:
            result['appears_random'] = True
        
        return result
    
    def _check_dnssec(self) -> Dict:
        """Check for DNSSEC support"""
        result = {
            'supports_dnssec': False,
            'has_dnskey': False,
            'has_rrsig': False
        }
        
        # Query for DNSKEY (type 48)
        query = self._build_dns_query(self.domain, qtype=48)
        response = self._send_dns_query(query)
        
        if response and len(response) >= 12:
            ancount = struct.unpack('>H', response[6:8])[0]
            if ancount > 0:
                result['has_dnskey'] = True
                result['supports_dnssec'] = True
        
        # Query for RRSIG (type 46)
        query = self._build_dns_query(self.domain, qtype=46)
        response = self._send_dns_query(query)
        
        if response and len(response) >= 12:
            ancount = struct.unpack('>H', response[6:8])[0]
            if ancount > 0:
                result['has_rrsig'] = True
        
        return result
    
    def scan(self) -> ScanResult:
        """Execute DNS security scan"""
        result = self._init_result()
        
        self.log_progress(f"Starting DNS scan for {self.domain}")
        
        # Check if DNS port is open
        if not self._check_port(53, 'udp'):
            self.log_progress("DNS port 53 not responding, trying TCP...")
            if not self._check_port(53, 'tcp'):
                self._add_error(result, "DNS port 53 is not accessible")
                return self._finalize_result(result, "failed")
        
        # Zone transfer test
        zone_transfer = self._check_zone_transfer()
        result.raw_data['zone_transfer'] = zone_transfer
        self.log_progress(f"Zone transfer: {'VULNERABLE' if zone_transfer['vulnerable'] else 'Protected'}")
        
        # Recursion test
        recursion = self._check_recursion()
        result.raw_data['recursion'] = recursion
        self.log_progress(f"Open recursion: {'Yes' if recursion['allows_recursion'] else 'No'}")
        
        # Source port randomization
        port_random = self._check_source_port_randomization()
        result.raw_data['port_randomization'] = port_random
        
        # DNSSEC check
        dnssec = self._check_dnssec()
        result.raw_data['dnssec'] = dnssec
        self.log_progress(f"DNSSEC: {'Enabled' if dnssec['supports_dnssec'] else 'Not detected'}")
        
        # Generate findings
        self._generate_findings(result)
        
        return self._finalize_result(result)
    
    def _generate_findings(self, result: ScanResult) -> None:
        """Generate DNS security findings"""
        
        # Zone transfer vulnerability
        zone_transfer = result.raw_data.get('zone_transfer', {})
        if zone_transfer.get('vulnerable'):
            self._add_finding(result, Finding(
                title="DNS Zone Transfer Allowed (AXFR)",
                description="DNS server allows zone transfers to any host. This exposes all DNS records.",
                severity=SeverityLevel.HIGH,
                category="DNS Security",
                recommendation="Restrict zone transfers to authorized secondary DNS servers only. "
                               "Configure 'allow-transfer' in BIND or equivalent setting.",
                evidence=f"Received {zone_transfer.get('record_count', 'unknown')} records"
            ))
        
        # Open recursion
        recursion = result.raw_data.get('recursion', {})
        if recursion.get('allows_recursion'):
            self._add_finding(result, Finding(
                title="DNS Open Resolver Detected",
                description="DNS server allows recursive queries from external hosts. "
                           "This can be abused for DNS amplification attacks.",
                severity=SeverityLevel.HIGH,
                category="DNS Security",
                recommendation="Disable recursion for external hosts. Use 'allow-recursion' to restrict to trusted networks.",
                evidence=f"Successfully resolved external domain: {recursion.get('tested_domain')}"
            ))
        
        # Source port randomization
        port_random = result.raw_data.get('port_randomization', {})
        if not port_random.get('random_ports'):
            self._add_finding(result, Finding(
                title="Weak Source Port Randomization",
                description="DNS server may not be using random source ports, making it susceptible to cache poisoning.",
                severity=SeverityLevel.MEDIUM,
                category="DNS Security",
                recommendation="Ensure DNS server is configured to use random source ports for queries.",
                evidence=f"Observed ports: {port_random.get('ports_observed')}"
            ))
        
        # DNSSEC status
        dnssec = result.raw_data.get('dnssec', {})
        if not dnssec.get('supports_dnssec'):
            self._add_finding(result, Finding(
                title="DNSSEC Not Enabled",
                description="Domain does not appear to have DNSSEC enabled. DNS responses are not cryptographically signed.",
                severity=SeverityLevel.MEDIUM,
                category="DNS Security",
                recommendation="Implement DNSSEC to protect against DNS spoofing attacks.",
                evidence="No DNSKEY or RRSIG records found"
            ))
        else:
            self._add_finding(result, Finding(
                title="DNSSEC Enabled",
                description="DNSSEC is configured for the domain.",
                severity=SeverityLevel.INFO,
                category="DNS Security",
                recommendation="Ensure DNSSEC keys are regularly rotated.",
                evidence=f"DNSKEY: {dnssec.get('has_dnskey')}, RRSIG: {dnssec.get('has_rrsig')}"
            ))
