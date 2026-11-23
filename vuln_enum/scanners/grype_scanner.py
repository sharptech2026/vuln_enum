"""Grype scanner wrapper for container vulnerability scanning."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any
from .base import BaseScanner, Finding, ScanResult


class GrypeScanner(BaseScanner):
    """Wrapper for Anchore Grype scanner."""

    @property
    def name(self) -> str:
        return "grype"

    @property
    def binary_name(self) -> str:
        return "grype"

    def build_command(self, targets: list[str], output_file: Path) -> list[str]:
        binary = self.find_binary()
        if not binary:
            return []

        # Grype scans one target at a time
        cmd = [binary]

        # Output format
        cmd.extend(["-o", "json", "--file", str(output_file)])

        # Severity
        severity = self.config.get("severity", ["Critical", "High", "Medium", "Low"])
        if severity:
            cmd.extend(["--severity", ",".join(severity)])

        # Only show fixed vulnerabilities if requested
        # cmd.append("--only-fixed")  # Optional

        # Quiet
        cmd.append("-q")

        return cmd

    def run(self, targets: list[str], output_dir: Path, scan_id: str, scope: str) -> ScanResult:
        """Run Grype against each target."""
        if not self.enabled:
            return ScanResult(scanner=self.name, errors=["Scanner disabled in config"])

        binary = self.find_binary()
        if not binary:
            return ScanResult(scanner=self.name, errors=["grype not found in PATH"])

        all_findings = []
        all_errors = []
        total_duration = 0.0
        targets_scanned = 0
        commands = []

        for target in targets:
            output_file = output_dir / f"grype_{targets_scanned}_results.json"
            cmd = self.build_command([target], output_file)
            cmd.append(target)
            cmd_str = " ".join(cmd)
            commands.append(cmd_str)

            if self.audit_logger:
                config_hash = str(hash(cmd_str))[:16]
                self.audit_logger.log_scanner_start(self.name, [target], config_hash)

            start_time = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=output_dir,
                )
                duration = (__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - start_time).total_seconds()
                total_duration += duration
                targets_scanned += 1

                if result.returncode != 0:
                    all_errors.append(f"Target {target}: exit {result.returncode}: {result.stderr[:200]}")
                else:
                    findings = self.parse_output(output_file, [target])
                    for f in findings:
                        f.scope = scope
                        f.scan_id = scan_id
                    all_findings.extend(findings)

                if self.audit_logger:
                    self.audit_logger.log_scanner_complete(
                        self.name, len(findings) if 'findings' in locals() else 0, duration,
                        [all_errors[-1]] if all_errors and all_errors[-1].startswith(f"Target {target}") else []
                    )

            except subprocess.TimeoutExpired:
                duration = (__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - start_time).total_seconds()
                total_duration += duration
                all_errors.append(f"Target {target}: timeout after 300s")
                if self.audit_logger:
                    self.audit_logger.log_scanner_complete(self.name, 0, duration, all_errors[-1:])
            except Exception as e:
                duration = (__import__("datetime").datetime.now(__import__("datetime").timezone.utc) - start_time).total_seconds()
                total_duration += duration
                all_errors.append(f"Target {target}: {type(e).__name__}: {e}")
                if self.audit_logger:
                    self.audit_logger.log_scanner_complete(self.name, 0, duration, all_errors[-1:])

        return ScanResult(
            scanner=self.name,
            findings=all_findings,
            errors=all_errors,
            duration_seconds=total_duration,
            targets_scanned=targets_scanned,
            command="; ".join(commands),
        )

    def parse_output(self, output_file: Path, targets: list[str]) -> list[Finding]:
        findings = []

        if not output_file.exists():
            return findings

        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Grype JSON structure: matches array
            matches = data.get("matches", [])
            target = data.get("source", {}).get("target", targets[0] if targets else "")
            target_type = data.get("source", {}).get("type", "image")

            for match in matches:
                finding = self._parse_match(match, target, target_type)
                if finding:
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError):
            pass

        return findings

    def _parse_match(self, match: dict[str, Any], target: str, target_type: str) -> Finding | None:
        """Parse Grype match result."""
        try:
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vulnerability.get("id", "")
            pkg_name = artifact.get("name", "")
            pkg_version = artifact.get("version", "")
            pkg_type = artifact.get("type", "")
            severity = vulnerability.get("severity", "UNKNOWN").upper()
            description = vulnerability.get("description", "")
            fix_versions = vulnerability.get("fix", {}).get("versions", [])
            cvss = vulnerability.get("cvss", [])
            references = vulnerability.get("references", [])
            related = vulnerability.get("relatedVulnerabilities", [])

            # Extract CVSS
            cvss_vector = ""
            cvss_score = 0.0
            for cvss_entry in cvss:
                if isinstance(cvss_entry, dict):
                    cvss_vector = cvss_entry.get("vector", "")
                    cvss_score = float(cvss_entry.get("score", 0)) or cvss_score

            # CVE IDs
            cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else []
            cve_ids.extend([r for r in related if r.startswith("CVE-")])

            evidence = {
                "target": target,
                "target_type": target_type,
                "package": pkg_name,
                "package_version": pkg_version,
                "package_type": pkg_type,
                "vulnerability_id": vuln_id,
                "fix_versions": fix_versions,
                "cvss": cvss,
            }

            return Finding(
                cve_ids=list(set(cve_ids)),
                title=f"{vuln_id}: {pkg_name} {pkg_version}" if vuln_id else f"{pkg_name} {pkg_version}",
                description=description[:1000],
                severity=severity,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                scanner="grype",
                template="vuln",
                tags=["container", "vuln", target_type, pkg_type, pkg_name] if pkg_name else ["container", "vuln", target_type],
                target_host=target,
                target_port=0,
                target_protocol="container",
                target_service=f"{pkg_name} {pkg_version}" if pkg_name else target_type,
                target_url=target,
                evidence=evidence,
                request="",
                response="",
                remediation=f"Update {pkg_name} to {' or '.join(fix_versions)}" if fix_versions else "Apply vendor patches",
                references=references,
            )
        except Exception:
            return None