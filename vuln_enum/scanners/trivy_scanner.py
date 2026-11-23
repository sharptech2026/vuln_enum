"""Trivy scanner wrapper for container/fs vulnerability scanning."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any
from .base import BaseScanner, Finding, ScanResult


class TrivyScanner(BaseScanner):
    """Wrapper for Aqua Trivy scanner."""

    @property
    def name(self) -> str:
        return "trivy"

    @property
    def binary_name(self) -> str:
        return "trivy"

    def build_command(self, targets: list[str], output_file: Path) -> list[str]:
        binary = self.find_binary()
        if not binary:
            return []

        # Trivy scans one target at a time (image, filesystem, git repo)
        # We'll handle multiple targets in run() method
        cmd = [binary]

        # Scan types
        scan_types = self.config.get("scan_types", ["vuln", "config"])
        if scan_types:
            cmd.extend(["--scanners", ",".join(scan_types)])

        # Severity
        severity = self.config.get("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        if severity:
            cmd.extend(["--severity", ",".join(severity)])

        # Output format
        cmd.extend(["-f", "json", "-o", str(output_file)])

        # Skip DB update if requested
        if self.config.get("skip_db_update", False):
            cmd.append("--skip-db-update")

        # Timeout
        timeout = self.config.get("timeout", 300)
        cmd.extend(["--timeout", f"{timeout}s"])

        # Quiet mode
        cmd.append("-q")

        return cmd

    def run(self, targets: list[str], output_dir: Path, scan_id: str, scope: str) -> ScanResult:
        """Run Trivy against each target (images, directories, repos)."""
        if not self.enabled:
            return ScanResult(scanner=self.name, errors=["Scanner disabled in config"])

        binary = self.find_binary()
        if not binary:
            return ScanResult(scanner=self.name, errors=["trivy not found in PATH"])

        all_findings = []
        all_errors = []
        total_duration = 0.0
        targets_scanned = 0
        commands = []

        for target in targets:
            output_file = output_dir / f"trivy_{targets_scanned}_results.json"
            cmd = self.build_command([target], output_file)
            cmd.append(target)  # Target at the end
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
                    timeout=self.config.get("timeout", 300),
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
                all_errors.append(f"Target {target}: timeout after {self.config.get('timeout', 300)}s")
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

            # Trivy JSON structure: Results array
            results = data.get("Results", [])
            target_name = data.get("ArtifactName", targets[0] if targets else "")

            for result in results:
                target = result.get("Target", target_name)
                target_type = result.get("Type", "unknown")
                vulnerabilities = result.get("Vulnerabilities", [])
                misconfigs = result.get("Misconfigurations", [])

                # Process vulnerabilities
                for vuln in vulnerabilities:
                    finding = self._parse_vulnerability(vuln, target, target_type)
                    if finding:
                        findings.append(finding)

                # Process misconfigurations
                for misconfig in misconfigs:
                    finding = self._parse_misconfiguration(misconfig, target, target_type)
                    if finding:
                        findings.append(finding)

        except (json.JSONDecodeError, KeyError):
            pass

        return findings

    def _parse_vulnerability(self, vuln: dict[str, Any], target: str, target_type: str) -> Finding | None:
        """Parse Trivy vulnerability result."""
        try:
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion", "")
            title = vuln.get("Title", vuln_id)
            description = vuln.get("Description", "")
            severity = vuln.get("Severity", "UNKNOWN").upper()
            cvss = vuln.get("CVSS", {})
            references = vuln.get("References", [])

            # Extract CVSS
            cvss_vector = ""
            cvss_score = 0.0
            for source, metrics in cvss.items():
                if isinstance(metrics, dict):
                    cvss_vector = metrics.get("Vector", "")
                    cvss_score = float(metrics.get("Score", 0)) or cvss_score

            # CVE IDs
            cve_ids = [vuln_id] if vuln_id.startswith("CVE-") else []

            # Target parsing
            target_host = target
            target_port = 0
            target_protocol = "container"
            target_service = f"{pkg_name} {installed_version}" if pkg_name else target_type

            evidence = {
                "target": target,
                "target_type": target_type,
                "package": pkg_name,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "vulnerability_id": vuln_id,
                "cvss": cvss,
            }

            return Finding(
                cve_ids=cve_ids,
                title=f"{vuln_id}: {title}" if vuln_id else title,
                description=description[:1000],
                severity=severity,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                scanner="trivy",
                template="vuln",
                tags=["container", "vuln", target_type, pkg_name] if pkg_name else ["container", "vuln", target_type],
                target_host=target_host,
                target_port=target_port,
                target_protocol=target_protocol,
                target_service=target_service,
                target_url=target,
                evidence=evidence,
                request="",
                response="",
                remediation=f"Update {pkg_name} to version {fixed_version or 'latest'}" if fixed_version else "Apply vendor patches",
                references=references,
            )
        except Exception:
            return None

    def _parse_misconfiguration(self, misconfig: dict[str, Any], target: str, target_type: str) -> Finding | None:
        """Parse Trivy misconfiguration result."""
        try:
            misconfig_id = misconfig.get("ID", "")
            title = misconfig.get("Title", misconfig_id)
            description = misconfig.get("Description", "")
            severity = misconfig.get("Severity", "UNKNOWN").upper()
            references = misconfig.get("References", [])
            namespace = misconfig.get("Namespace", "")
            query = misconfig.get("Query", "")

            evidence = {
                "target": target,
                "target_type": target_type,
                "misconfig_id": misconfig_id,
                "namespace": namespace,
                "query": query,
                "resolution": misconfig.get("Resolution", ""),
            }

            return Finding(
                cve_ids=[],
                title=f"Misconfig: {title}",
                description=description[:1000],
                severity=severity,
                scanner="trivy",
                template="config",
                tags=["container", "config", "misconfig", namespace] if namespace else ["container", "config", "misconfig"],
                target_host=target,
                target_port=0,
                target_protocol="container",
                target_service=target_type,
                target_url=target,
                evidence=evidence,
                request="",
                response="",
                remediation=misconfig.get("Resolution", "Review and remediate configuration issue"),
                references=references,
            )
        except Exception:
            return None