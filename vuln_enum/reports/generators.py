"""Report generators for multiple output formats."""

from __future__ import annotations
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dataclasses import asdict

from ..scanners.base import Finding, ScanResult
from ..utils.audit import AuditReader
from ..config.models import SeverityLevel


class ReportGenerator:
    """Generates reports in multiple formats from scan findings."""

    def __init__(self, findings: list[Finding], scan_results: list[ScanResult],
                 scan_id: str, scope_name: str, config: dict[str, Any] | None = None):
        self.findings = findings
        self.scan_results = scan_results
        self.scan_id = scan_id
        self.scope_name = scope_name
        self.config = config or {}
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def get_summary(self) -> dict[str, Any]:
        """Get scan summary statistics."""
        by_severity = {}
        by_scanner = {}
        by_target = {}

        for f in self.findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_scanner[f.scanner] = by_scanner.get(f.scanner, 0) + 1
            target = f"{f.target_host}:{f.target_port}" if f.target_port else f.target_host
            by_target[target] = by_target.get(target, 0) + 1

        total_duration = sum(r.duration_seconds for r in self.scan_results)

        return {
            "scan_id": self.scan_id,
            "scope": self.scope_name,
            "generated_at": self.generated_at,
            "tool": "vuln_enum",
            "version": "1.0.0",
            "developed_by": "Security Research Team",
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "by_scanner": by_scanner,
            "unique_targets": len(by_target),
            "targets_with_findings": by_target,
            "scanners_run": [r.scanner for r in self.scan_results],
            "total_duration_seconds": round(total_duration, 2),
            "scanner_details": [
                {
                    "scanner": r.scanner,
                    "findings": len(r.findings),
                    "errors": len(r.errors),
                    "duration_seconds": round(r.duration_seconds, 2),
                    "targets_scanned": r.targets_scanned,
                }
                for r in self.scan_results
            ],
        }

    def generate_json(self, output_file: Path, include_evidence: bool = True) -> Path:
        """Generate JSON report."""
        data = {
            "metadata": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

        if not include_evidence:
            for f in data["findings"]:
                f.pop("evidence", None)
                f.pop("request", None)
                f.pop("response", None)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return output_file

    def generate_sarif(self, output_file: Path) -> Path:
        """Generate SARIF report for GitHub/CodeQL integration."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "vuln_enum",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/vuln-enum",
                        "rules": [],
                    }
                },
                "results": [],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": self.generated_at,
                    "toolConfigurationNotifications": [],
                }]
            }]
        }

        # Build rules from unique finding templates
        rules_map = {}
        for finding in self.findings:
            rule_id = finding.template or finding.id
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.description[:500]},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": self._severity_to_sarif_level(finding.severity)},
                    "helpUri": finding.references[0] if finding.references else "",
                    "properties": {
                        "tags": finding.tags,
                        "scanner": finding.scanner,
                    },
                }

        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

        # Build results
        for finding in self.findings:
            rule_id = finding.template or finding.id
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(finding.severity),
                "message": {"text": finding.title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.target_url or finding.target_host,
                        },
                        "region": {
                            "startLine": 1,
                        }
                    }
                }],
                "properties": {
                    "severity": finding.severity,
                    "cvssScore": finding.cvss_score,
                    "cveIds": finding.cve_ids,
                    "scanner": finding.scanner,
                    "target": finding.target_host,
                    "port": finding.target_port,
                }
            }
            sarif["runs"][0]["results"].append(result)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif, f, ensure_ascii=False, indent=2)

        return output_file

    def _severity_to_sarif_level(self, severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity.upper(), "note")

    def generate_markdown(self, output_file: Path, executive: bool = True) -> Path:
        """Generate Markdown report."""
        summary = self.get_summary()

        lines = []
        lines.append(f"# Vulnerability Assessment Report")
        lines.append("")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Scope:** {self.scope_name}")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append(f"**Tool:** vuln_enum v1.0.0")
        lines.append(f"**Developed by:** Security Research Team")
        lines.append("")

        if executive:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(f"This assessment identified **{summary['total_findings']}** vulnerabilities across **{summary['unique_targets']}** unique targets.")
            lines.append("")

            # Severity breakdown
            lines.append("### Findings by Severity")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = summary["by_severity"].get(sev, 0)
                if count > 0:
                    lines.append(f"| {sev} | {count} |")
            lines.append("")

            # Top affected targets
            lines.append("### Most Affected Targets")
            lines.append("")
            lines.append("| Target | Findings |")
            lines.append("|--------|----------|")
            sorted_targets = sorted(summary["targets_with_findings"].items(), key=lambda x: -x[1])
            for target, count in sorted_targets[:10]:
                lines.append(f"| {target} | {count} |")
            lines.append("")

            # Scanner summary
            lines.append("### Scanners Executed")
            lines.append("")
            lines.append("| Scanner | Findings | Targets Scanned | Duration (s) | Errors |")
            lines.append("|---------|----------|-----------------|--------------|--------|")
            for sd in summary["scanner_details"]:
                lines.append(f"| {sd['scanner']} | {sd['findings']} | {sd['targets_scanned']} | {sd['duration_seconds']} | {sd['errors']} |")
            lines.append("")

        # Detailed findings
        lines.append("## Detailed Findings")
        lines.append("")

        # Group by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if not sev_findings:
                continue

            lines.append(f"### {sev} Severity ({len(sev_findings)} findings)")
            lines.append("")

            for finding in sev_findings:
                lines.append(f"#### {finding.title}")
                lines.append("")
                lines.append(f"- **ID:** {finding.id}")
                if finding.cve_ids:
                    lines.append(f"- **CVE(s):** {', '.join(finding.cve_ids)}")
                lines.append(f"- **Severity:** {finding.severity}")
                if finding.cvss_score:
                    lines.append(f"- **CVSS Score:** {finding.cvss_score}")
                lines.append(f"- **Scanner(s):** {finding.scanner}")
                lines.append(f"- **Template:** {finding.template}")
                lines.append(f"- **Target:** {finding.target_host}:{finding.target_port}" if finding.target_port else f"- **Target:** {finding.target_host}")
                if finding.target_service:
                    lines.append(f"- **Service:** {finding.target_service}")
                if finding.target_url:
                    lines.append(f"- **URL:** {finding.target_url}")
                lines.append(f"- **Tags:** {', '.join(finding.tags)}")
                lines.append("")
                lines.append(f"**Description:** {finding.description}")
                lines.append("")
                if finding.remediation:
                    lines.append(f"**Remediation:** {finding.remediation}")
                    lines.append("")
                if finding.references:
                    lines.append("**References:**")
                    for ref in finding.references[:5]:
                        lines.append(f"- {ref}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return output_file

    def generate_html(self, output_file: Path) -> Path:
        """Generate HTML report with embedded CSS/JS."""
        summary = self.get_summary()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>vuln_enum Report - {self.scan_id}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; background: #fafafa; }}
        .header {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; margin-top: 10px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ margin: 0 0 10px; font-size: 14px; color: #666; text-transform: uppercase; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .severity-critical {{ color: #dc2626; }}
        .severity-high {{ color: #ea580c; }}
        .severity-medium {{ color: #d97706; }}
        .severity-low {{ color: #2563eb; }}
        .severity-info {{ color: #64748b; }}
        .scanner-table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .scanner-table th, .scanner-table td {{ padding: 12px 16px; text-align: left; border-bottom: 1px solid #eee; }}
        .scanner-table th {{ background: #f8fafc; font-weight: 600; }}
        .finding {{ background: white; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
        .finding-header {{ padding: 16px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }}
        .finding-title {{ margin: 0; font-size: 18px; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #fef2f2; color: #dc2626; }}
        .severity-badge.high {{ background: #fff7ed; color: #ea580c; }}
        .severity-badge.medium {{ background: #fffbeb; color: #d97706; }}
        .severity-badge.low {{ background: #eff6ff; color: #2563eb; }}
        .severity-badge.info {{ background: #f1f5f9; color: #64748b; }}
        .finding-body {{ padding: 20px; }}
        .finding-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; font-size: 14px; }}
        .finding-meta dt {{ color: #666; font-weight: 500; }}
        .finding-meta dd {{ margin: 0; color: #333; }}
        .finding-description {{ background: #f8fafc; padding: 16px; border-radius: 6px; margin-bottom: 16px; }}
        .finding-remediation {{ background: #f0fdf4; padding: 16px; border-radius: 6px; border-left: 4px solid #16a34a; }}
        .finding-remediation strong {{ color: #166534; }}
        .references {{ margin-top: 12px; font-size: 13px; }}
        .references a {{ color: #3b82f6; text-decoration: none; }}
        .references a:hover {{ text-decoration: underline; }}
        .filter-bar {{ margin-bottom: 20px; padding: 16px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .filter-bar select, .filter-bar input {{ padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; margin-right: 10px; }}
        @media (max-width: 768px) {{ .finding-meta {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Assessment Report</h1>
        <div class="meta">
            Scan ID: {self.scan_id} | Scope: {self.scope_name} | Generated: {self.generated_at} | vuln_enum v1.0.0
        </div>
    </div>

    <div class="summary-grid">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <div class="value">{summary['total_findings']}</div>
        </div>
        <div class="stat-card">
            <h3>Unique Targets</h3>
            <div class="value">{summary['unique_targets']}</div>
        </div>
        <div class="stat-card">
            <h3>Scanners Run</h3>
            <div class="value">{len(summary['scanners_run'])}</div>
        </div>
        <div class="stat-card">
            <h3>Duration</h3>
            <div class="value">{summary['total_duration_seconds']}s</div>
        </div>
    </div>

    <div class="summary-grid">
"""

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = summary["by_severity"].get(sev, 0)
            if count > 0:
                html += f"""
        <div class="stat-card">
            <h3>{sev} Severity</h3>
            <div class="value severity-{sev.lower()}">{count}</div>
        </div>"""

        html += """
    </div>

    <table class="scanner-table">
        <thead>
            <tr><th>Scanner</th><th>Findings</th><th>Targets Scanned</th><th>Duration (s)</th><th>Errors</th></tr>
        </thead>
        <tbody>
"""

        for sd in summary["scanner_details"]:
            html += f"""            <tr>
                <td>{sd['scanner']}</td>
                <td>{sd['findings']}</td>
                <td>{sd['targets_scanned']}</td>
                <td>{sd['duration_seconds']}</td>
                <td>{sd['errors']}</td>
            </tr>"""

        html += """
        </tbody>
    </table>

    <div class="filter-bar">
        <label>Filter by severity:
            <select id="severityFilter">
                <option value="">All</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFO">INFO</option>
            </select>
        </label>
        <label>Search:
            <input type="text" id="searchFilter" placeholder="Search findings...">
        </label>
    </div>

    <div id="findingsContainer">
"""

        # Group findings by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if not sev_findings:
                continue

            for finding in sev_findings:
                html += f"""
        <div class="finding" data-severity="{finding.severity}" data-search="{finding.title} {finding.target_host} {finding.template} {' '.join(finding.cve_ids)}">
            <div class="finding-header">
                <h3 class="finding-title">{finding.title}</h3>
                <span class="severity-badge {finding.severity.lower()}">{finding.severity}</span>
            </div>
            <div class="finding-body">
                <dl class="finding-meta">
                    <dt>Finding ID</dt><dd>{finding.id}</dd>
                    {'<dt>CVE(s)</dt><dd>' + ', '.join(finding.cve_ids) + '</dd>' if finding.cve_ids else ''}
                    <dt>Scanner(s)</dt><dd>{finding.scanner}</dd>
                    <dt>Template</dt><dd>{finding.template}</dd>
                    <dt>Target</dt><dd>{finding.target_host}:{finding.target_port}</dd>
                    {'<dt>Service</dt><dd>' + finding.target_service + '</dd>' if finding.target_service else ''}
                    {'<dt>URL</dt><dd><a href="' + finding.target_url + '" target="_blank">' + finding.target_url + '</a></dd>' if finding.target_url else ''}
                    <dt>Tags</dt><dd>{', '.join(finding.tags)}</dd>
                    {'<dt>CVSS Score</dt><dd>' + str(finding.cvss_score) + '</dd>' if finding.cvss_score else ''}
                </dl>
                <div class="finding-description"><strong>Description:</strong> {finding.description}</div>
                {'<div class="finding-remediation"><strong>Remediation:</strong> ' + finding.remediation + '</div>' if finding.remediation else ''}
                {'<div class="references"><strong>References:</strong><br>' + '<br>'.join(['<a href="' + r + '" target="_blank">' + r + '</a>' for r in finding.references[:10]]) + '</div>' if finding.references else ''}
            </div>
        </div>"""

        html += f"""
    </div>

    <script>
        const severityFilter = document.getElementById('severityFilter');
        const searchFilter = document.getElementById('searchFilter');
        const findings = document.querySelectorAll('.finding');

        function filterFindings() {{
            const severity = severityFilter.value;
            const search = searchFilter.value.toLowerCase();
            findings.forEach(f => {{
                const matchSeverity = !severity || f.dataset.severity === severity;
                const matchSearch = !search || f.dataset.search.toLowerCase().includes(search);
                f.style.display = matchSeverity && matchSearch ? 'block' : 'none';
            }});
        }}

        severityFilter.addEventListener('change', filterFindings);
        searchFilter.addEventListener('input', filterFindings);
    </script>
</body>
</html>"""

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def generate_csv(self, output_file: Path) -> Path:
        """Generate CSV report for spreadsheet import."""
        fieldnames = [
            "scan_id", "scope", "finding_id", "cve_ids", "title", "description",
            "severity", "cvss_score", "cvss_vector", "scanner", "template", "tags",
            "target_host", "target_port", "target_protocol", "target_service", "target_url",
            "remediation", "references", "matched_at"
        ]

        with open(output_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for finding in self.findings:
                row = {
                    "scan_id": self.scan_id,
                    "scope": self.scope_name,
                    "finding_id": finding.id,
                    "cve_ids": ";".join(finding.cve_ids),
                    "title": finding.title,
                    "description": finding.description[:500],
                    "severity": finding.severity,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                    "scanner": finding.scanner,
                    "template": finding.template,
                    "tags": ";".join(finding.tags),
                    "target_host": finding.target_host,
                    "target_port": finding.target_port,
                    "target_protocol": finding.target_protocol,
                    "target_service": finding.target_service,
                    "target_url": finding.target_url,
                    "remediation": finding.remediation,
                    "references": ";".join(finding.references),
                    "matched_at": finding.matched_at,
                }
                writer.writerow(row)

        return output_file


def generate_all_reports(findings: list[Finding], scan_results: list[ScanResult],
                         scan_id: str, scope_name: str, output_dir: Path,
                         formats: list[str] = None, config: dict[str, Any] = None) -> list[Path]:
    """Generate reports in all requested formats."""
    if formats is None:
        formats = ["json", "markdown", "html", "sarif", "csv"]

    generator = ReportGenerator(findings, scan_results, scan_id, scope_name, config)
    output_files = []

    for fmt in formats:
        try:
            if fmt == "json":
                output_files.append(generator.generate_json(output_dir / "findings.json"))
            elif fmt == "sarif":
                output_files.append(generator.generate_sarif(output_dir / "findings.sarif"))
            elif fmt == "markdown":
                output_files.append(generator.generate_markdown(output_dir / "report.md"))
            elif fmt == "html":
                output_files.append(generator.generate_html(output_dir / "report.html"))
            elif fmt == "csv":
                output_files.append(generator.generate_csv(output_dir / "findings.csv"))
        except Exception as e:
            print(f"Warning: Failed to generate {fmt} report: {e}")

    return output_files