"""
Professional Security Report Generator
Generates comprehensive penetration testing reports
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

from scanners.base_scanner import ScanResult, SeverityLevel


class ReportGenerator:
    """
    Professional Security Report Generator
    - HTML Report
    - JSON Report
    - Text Report
    - Executive Summary
    """
    
    def __init__(self, target: str, scan_results: List[ScanResult]):
        self.target = target
        self.scan_results = scan_results
        self.report_time = datetime.now()
        
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d'
        }
        return colors.get(severity, '#6c757d')
    
    def _get_severity_badge(self, severity: str) -> str:
        """Get HTML badge for severity"""
        color = self._get_severity_color(severity)
        return f'<span style="background-color: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px;">{severity}</span>'
    
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
    
    def generate_html_report(self, output_path: str) -> str:
        """Generate comprehensive HTML report"""
        findings = self._aggregate_findings()
        risk = self._calculate_risk_score()
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report - {self.target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header .subtitle {{ opacity: 0.8; font-size: 1.2em; }}
        .meta-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }}
        .meta-item {{ background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px; }}
        .meta-item label {{ font-size: 0.8em; opacity: 0.7; display: block; }}
        .meta-item span {{ font-size: 1.2em; font-weight: 600; }}
        
        .risk-overview {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .risk-score {{ display: flex; align-items: center; gap: 30px; }}
        .score-circle {{ width: 150px; height: 150px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; font-weight: bold; }}
        .score-circle .number {{ font-size: 3em; }}
        .score-circle .label {{ font-size: 0.9em; opacity: 0.9; }}
        
        .findings-summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; flex: 1; }}
        .finding-count {{ text-align: center; padding: 20px; border-radius: 8px; color: white; }}
        .finding-count .count {{ font-size: 2em; font-weight: bold; }}
        .finding-count .label {{ font-size: 0.9em; }}
        
        .section {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px; margin-bottom: 20px; }}
        
        .finding-card {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px; margin-bottom: 15px; border-left: 4px solid; }}
        .finding-card.critical {{ border-left-color: #dc3545; }}
        .finding-card.high {{ border-left-color: #fd7e14; }}
        .finding-card.medium {{ border-left-color: #ffc107; }}
        .finding-card.low {{ border-left-color: #17a2b8; }}
        .finding-card.info {{ border-left-color: #6c757d; }}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.1em; font-weight: 600; color: #1a1a2e; }}
        .finding-meta {{ font-size: 0.85em; color: #666; margin-bottom: 10px; }}
        .finding-description {{ margin-bottom: 15px; }}
        .finding-recommendation {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
        .finding-recommendation strong {{ color: #28a745; }}
        .finding-evidence {{ background: #f1f3f5; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 0.9em; margin-top: 10px; }}
        
        .scanner-results {{ margin-top: 20px; }}
        .scanner-card {{ border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
        .scanner-header {{ background: #f8f9fa; padding: 15px; font-weight: 600; cursor: pointer; display: flex; justify-content: space-between; }}
        .scanner-body {{ padding: 20px; display: none; }}
        .scanner-body.active {{ display: block; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: white; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #17a2b8; }}
        .badge-info {{ background: #6c757d; }}
        
        footer {{ text-align: center; padding: 30px; color: #666; }}
        
        @media print {{
            .scanner-body {{ display: block !important; }}
            body {{ background: white; }}
            .section, .risk-overview {{ box-shadow: none; border: 1px solid #ddd; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Penetration Test Report</h1>
            <p class="subtitle">Comprehensive Security Assessment</p>
            <div class="meta-info">
                <div class="meta-item">
                    <label>Target</label>
                    <span>{self.target}</span>
                </div>
                <div class="meta-item">
                    <label>Report Date</label>
                    <span>{self.report_time.strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                <div class="meta-item">
                    <label>Scanners Used</label>
                    <span>{len(self.scan_results)}</span>
                </div>
                <div class="meta-item">
                    <label>Total Findings</label>
                    <span>{sum(risk['findings_count'].values())}</span>
                </div>
            </div>
        </header>
        
        <div class="risk-overview">
            <h2 style="margin-bottom: 20px;">📊 Risk Overview</h2>
            <div class="risk-score">
                <div class="score-circle" style="background: {self._get_severity_color(risk['level'])};">
                    <span class="number">{risk['score']}</span>
                    <span class="label">{risk['level']} RISK</span>
                </div>
                <div class="findings-summary">
                    <div class="finding-count" style="background: #dc3545;">
                        <div class="count">{risk['findings_count']['CRITICAL']}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="finding-count" style="background: #fd7e14;">
                        <div class="count">{risk['findings_count']['HIGH']}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="finding-count" style="background: #ffc107; color: #333;">
                        <div class="count">{risk['findings_count']['MEDIUM']}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="finding-count" style="background: #17a2b8;">
                        <div class="count">{risk['findings_count']['LOW']}</div>
                        <div class="label">Low</div>
                    </div>
                    <div class="finding-count" style="background: #6c757d;">
                        <div class="count">{risk['findings_count']['INFO']}</div>
                        <div class="label">Info</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Executive Summary</h2>
            <p>This penetration test was conducted against <strong>{self.target}</strong> on {self.report_time.strftime('%B %d, %Y')}. 
            The assessment identified <strong>{sum(risk['findings_count'].values())}</strong> findings across multiple security categories.</p>
            
            <h3 style="margin: 20px 0 10px 0;">Key Findings:</h3>
            <ul style="margin-left: 20px;">
                {''.join(f"<li><strong>{f['title']}</strong> - {f['description'][:100]}...</li>" for f in findings['CRITICAL'][:3])}
                {''.join(f"<li><strong>{f['title']}</strong> - {f['description'][:100]}...</li>" for f in findings['HIGH'][:3])}
            </ul>
            
            <h3 style="margin: 20px 0 10px 0;">Overall Risk Assessment:</h3>
            <p>Based on the findings, the overall security posture is rated as <strong style="color: {self._get_severity_color(risk['level'])};">{risk['level']}</strong>. 
            Immediate attention is required for {risk['findings_count']['CRITICAL']} critical and {risk['findings_count']['HIGH']} high severity findings.</p>
        </div>
'''
        
        # Add findings sections by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if findings[severity]:
                html += f'''
        <div class="section">
            <h2>{self._get_severity_badge(severity)} {severity} Findings ({len(findings[severity])})</h2>
'''
                for finding in findings[severity]:
                    html += f'''
            <div class="finding-card {severity.lower()}">
                <div class="finding-header">
                    <span class="finding-title">{finding['title']}</span>
                    <span class="badge badge-{severity.lower()}">{severity}</span>
                </div>
                <div class="finding-meta">
                    <strong>Category:</strong> {finding['category']} | 
                    <strong>Scanner:</strong> {finding['scanner']}
                    {f" | <strong>CVEs:</strong> {', '.join(finding['cve_ids'])}" if finding.get('cve_ids') else ''}
                </div>
                <div class="finding-description">{finding['description']}</div>
                <div class="finding-recommendation">
                    <strong>✅ Recommendation:</strong> {finding['recommendation']}
                </div>
                {f'<div class="finding-evidence"><strong>Evidence:</strong> {finding["evidence"]}</div>' if finding.get('evidence') else ''}
            </div>
'''
                html += '        </div>\n'
        
        # Add scanner details section
        html += '''
        <div class="section">
            <h2>🔍 Scanner Details</h2>
            <div class="scanner-results">
'''
        
        for result in self.scan_results:
            result_dict = result.to_dict()
            html += f'''
                <div class="scanner-card">
                    <div class="scanner-header" onclick="this.nextElementSibling.classList.toggle('active')">
                        <span>{result.scanner_name}</span>
                        <span>{result_dict['summary']['total_findings']} findings</span>
                    </div>
                    <div class="scanner-body">
                        <table>
                            <tr><th>Start Time</th><td>{result_dict['start_time']}</td></tr>
                            <tr><th>End Time</th><td>{result_dict['end_time']}</td></tr>
                            <tr><th>Status</th><td>{result_dict['status']}</td></tr>
                            <tr><th>Critical</th><td>{result_dict['summary']['critical']}</td></tr>
                            <tr><th>High</th><td>{result_dict['summary']['high']}</td></tr>
                            <tr><th>Medium</th><td>{result_dict['summary']['medium']}</td></tr>
                            <tr><th>Low</th><td>{result_dict['summary']['low']}</td></tr>
                            <tr><th>Info</th><td>{result_dict['summary']['info']}</td></tr>
                        </table>
                        {f"<p style='color: red; margin-top: 10px;'><strong>Errors:</strong> {', '.join(result_dict['errors'])}</p>" if result_dict['errors'] else ''}
                    </div>
                </div>
'''
        
        html += '''
            </div>
        </div>
        
        <footer>
            <p>Generated by Penetration Testing Toolkit</p>
            <p style="font-size: 0.9em; opacity: 0.7;">For authorized security testing only</p>
        </footer>
    </div>
</body>
</html>'''
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_path
    
    def generate_json_report(self, output_path: str) -> str:
        """Generate JSON report"""
        report = {
            'metadata': {
                'target': self.target,
                'report_time': self.report_time.isoformat(),
                'toolkit_version': '1.0.0'
            },
            'risk_assessment': self._calculate_risk_score(),
            'findings': self._aggregate_findings(),
            'scan_results': [r.to_dict() for r in self.scan_results]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_path
    
    def generate_text_report(self, output_path: str) -> str:
        """Generate plain text report"""
        findings = self._aggregate_findings()
        risk = self._calculate_risk_score()
        
        lines = [
            "=" * 80,
            "PENETRATION TEST REPORT",
            "=" * 80,
            "",
            f"Target: {self.target}",
            f"Report Date: {self.report_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Risk Score: {risk['score']}/100 ({risk['level']})",
            "",
            "-" * 80,
            "FINDINGS SUMMARY",
            "-" * 80,
            f"Critical: {risk['findings_count']['CRITICAL']}",
            f"High: {risk['findings_count']['HIGH']}",
            f"Medium: {risk['findings_count']['MEDIUM']}",
            f"Low: {risk['findings_count']['LOW']}",
            f"Info: {risk['findings_count']['INFO']}",
            "",
        ]
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if findings[severity]:
                lines.append("-" * 80)
                lines.append(f"{severity} FINDINGS")
                lines.append("-" * 80)
                lines.append("")
                
                for i, finding in enumerate(findings[severity], 1):
                    lines.append(f"[{severity}] {i}. {finding['title']}")
                    lines.append(f"   Category: {finding['category']}")
                    lines.append(f"   Description: {finding['description']}")
                    lines.append(f"   Recommendation: {finding['recommendation']}")
                    if finding.get('evidence'):
                        lines.append(f"   Evidence: {finding['evidence']}")
                    if finding.get('cve_ids'):
                        lines.append(f"   CVEs: {', '.join(finding['cve_ids'])}")
                    lines.append("")
        
        lines.extend([
            "=" * 80,
            "END OF REPORT",
            "=" * 80,
        ])
        
        content = '\n'.join(lines)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return output_path
    
    def print_summary(self) -> None:
        """Print summary to console"""
        risk = self._calculate_risk_score()
        
        print("\n" + "=" * 60)
        print("📊 SCAN SUMMARY")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Risk Score: {risk['score']}/100 ({risk['level']})")
        print("-" * 60)
        print(f"🔴 Critical: {risk['findings_count']['CRITICAL']}")
        print(f"🟠 High: {risk['findings_count']['HIGH']}")
        print(f"🟡 Medium: {risk['findings_count']['MEDIUM']}")
        print(f"🔵 Low: {risk['findings_count']['LOW']}")
        print(f"⚪ Info: {risk['findings_count']['INFO']}")
        print("=" * 60)
