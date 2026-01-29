"""
ShadowRecon - Professional Security Report Generator
Generates comprehensive penetration testing reports in JSON and Markdown formats
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from scanners.base_scanner import ScanResult, SeverityLevel


class ReportGenerator:
    """
    Professional Security Report Generator
    - JSON Report (machine-readable)
    - Markdown Report (human-readable)
    """
    
    def __init__(self, target: str, scan_results: List[ScanResult], tor_ip: Optional[str] = None):
        self.target = target
        self.scan_results = scan_results
        self.report_time = datetime.now()
        self.tor_ip = tor_ip
    
    def _aggregate_findings(self) -> Dict[str, List[Dict]]:
        """Aggregate findings from all scans by severity"""
        aggregated = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }
        
        for result in self.scan_results:
            for finding in result.findings:
                finding_dict = finding.to_dict()
                finding_dict['scanner'] = result.scanner_name
                aggregated[finding.severity.value].append(finding_dict)
        
        return aggregated
    
    def _calculate_risk_score(self) -> Dict:
        """Calculate overall risk score"""
        findings = self._aggregate_findings()
        
        # Weighted scoring
        weights = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 10,
            'LOW': 3,
            'INFO': 0
        }
        
        total_score = 0
        max_possible = 100
        
        for severity, items in findings.items():
            total_score += len(items) * weights[severity]
        
        # Cap at 100
        risk_score = min(total_score, 100)
        
        # Risk level
        if risk_score >= 75:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 25:
            risk_level = 'MEDIUM'
        elif risk_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'score': risk_score,
            'level': risk_level,
            'findings_count': {s: len(f) for s, f in findings.items()}
        }
    
    def generate_json_report(self, output_path: str) -> str:
        """Generate JSON report"""
        report = {
            'metadata': {
                'tool': 'ShadowRecon',
                'version': '3.0',
                'target': self.target,
                'report_time': self.report_time.isoformat(),
                'tor_exit_ip': self.tor_ip,
                'scan_mode': 'stealth_tor'
            },
            'risk_assessment': self._calculate_risk_score(),
            'findings': self._aggregate_findings(),
            'scan_results': [r.to_dict() for r in self.scan_results]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_path
    
    def generate_markdown_report(self, output_path: str) -> str:
        """Generate comprehensive Markdown report"""
        findings = self._aggregate_findings()
        risk = self._calculate_risk_score()
        
        lines = [
            f"# 🔮 ShadowRecon Security Report",
            "",
            f"## Target: `{self.target}`",
            "",
            "---",
            "",
            "## 📋 Scan Metadata",
            "",
            "| Property | Value |",
            "|----------|-------|",
            f"| **Target** | `{self.target}` |",
            f"| **Scan Date** | {self.report_time.strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Tor Exit IP** | `{self.tor_ip or 'N/A'}` |",
            f"| **Scanners Used** | {len(self.scan_results)} |",
            f"| **Total Findings** | {sum(risk['findings_count'].values())} |",
            "",
            "---",
            "",
            "## 📊 Risk Assessment",
            "",
            f"### Overall Risk Score: **{risk['score']}/100** ({risk['level']})",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {risk['findings_count']['CRITICAL']} |",
            f"| 🟠 High | {risk['findings_count']['HIGH']} |",
            f"| 🟡 Medium | {risk['findings_count']['MEDIUM']} |",
            f"| 🔵 Low | {risk['findings_count']['LOW']} |",
            f"| ⚪ Info | {risk['findings_count']['INFO']} |",
            "",
            "---",
            "",
            "## 📝 Executive Summary",
            "",
            f"This penetration test was conducted against **{self.target}** on {self.report_time.strftime('%B %d, %Y')}.",
            f"All traffic was routed through the Tor network for anonymity (Exit IP: `{self.tor_ip or 'N/A'}`).",
            "",
            f"The assessment identified **{sum(risk['findings_count'].values())}** findings across multiple security categories.",
            f"Based on the findings, the overall security posture is rated as **{risk['level']}**.",
            "",
        ]
        
        # Key findings
        if findings['CRITICAL'] or findings['HIGH']:
            lines.extend([
                "### ⚠️ Key Findings Requiring Immediate Attention:",
                "",
            ])
            for f in findings['CRITICAL'][:5]:
                lines.append(f"- **[CRITICAL]** {f['title']}")
            for f in findings['HIGH'][:5]:
                lines.append(f"- **[HIGH]** {f['title']}")
            lines.append("")
        
        lines.extend([
            "---",
            "",
        ])
        
        # Detailed findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if findings[severity]:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFO': '⚪'}[severity]
                lines.extend([
                    f"## {emoji} {severity} Findings ({len(findings[severity])})",
                    "",
                ])
                
                for i, finding in enumerate(findings[severity], 1):
                    lines.extend([
                        f"### {i}. {finding['title']}",
                        "",
                        f"**Category:** {finding['category']} | **Scanner:** {finding['scanner']}",
                        "",
                        f"**Description:**",
                        f"> {finding['description']}",
                        "",
                        f"**Recommendation:**",
                        f"> ✅ {finding['recommendation']}",
                        "",
                    ])
                    
                    if finding.get('evidence'):
                        lines.extend([
                            f"**Evidence:**",
                            f"```",
                            f"{finding['evidence']}",
                            f"```",
                            "",
                        ])
                    
                    if finding.get('cve_ids'):
                        lines.append(f"**CVEs:** {', '.join(finding['cve_ids'])}")
                        lines.append("")
                    
                    lines.append("---")
                    lines.append("")
        
        # Scanner details
        lines.extend([
            "## 🔍 Scanner Details",
            "",
        ])
        
        for result in self.scan_results:
            result_dict = result.to_dict()
            status_emoji = "✅" if result.status == "completed" else "❌"
            lines.extend([
                f"### {status_emoji} {result.scanner_name}",
                "",
                f"| Property | Value |",
                f"|----------|-------|",
                f"| Status | {result.status} |",
                f"| Start Time | {result_dict['start_time']} |",
                f"| End Time | {result_dict['end_time'] or 'N/A'} |",
                f"| Findings | {result_dict['summary']['total_findings']} |",
                "",
            ])
            
            if result_dict['errors']:
                lines.append(f"**Errors:** {', '.join(result_dict['errors'])}")
                lines.append("")
        
        # Footer
        lines.extend([
            "---",
            "",
            "## 📌 Disclaimer",
            "",
            "> This report was generated by **ShadowRecon v3.0** - Stealth Security Reconnaissance Framework.",
            "> All scans were conducted through the Tor network for anonymity.",
            "> This tool is intended for **authorized security testing only**.",
            "> Unauthorized access to computer systems is illegal.",
            "",
            f"*Report generated: {self.report_time.strftime('%Y-%m-%d %H:%M:%S')}*",
        ])
        
        content = '\n'.join(lines)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_path
    
    def print_summary(self) -> None:
        """Print summary to console"""
        risk = self._calculate_risk_score()
        
        print("\n" + "=" * 60)
        print("📊 SHADOWRECON SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Tor Exit IP: {self.tor_ip or 'N/A'}")
        print(f"Risk Score: {risk['score']}/100 ({risk['level']})")
        print("-" * 60)
        print(f"🔴 Critical: {risk['findings_count']['CRITICAL']}")
        print(f"🟠 High: {risk['findings_count']['HIGH']}")
        print(f"🟡 Medium: {risk['findings_count']['MEDIUM']}")
        print(f"🔵 Low: {risk['findings_count']['LOW']}")
        print(f"⚪ Info: {risk['findings_count']['INFO']}")
        print("=" * 60)
