"""Nuclei scanner wrapper."""

from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any
from .base import BaseScanner, Finding, ScanResult


class NucleiScanner(BaseScanner):
    """Wrapper for ProjectDiscovery Nuclei scanner."""

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def binary_name(self) -> str:
        return "nuclei"

    def build_command(self, targets: list[str], output_file: Path) -> list[str]:
        cmd = [self.find_binary()]

        # Target specification
        if len(targets) == 1 and not Path(targets[0]).exists():
            # Single target (URL, IP, hostname)
            cmd.extend(["-u", targets[0]])
        else:
            # Multiple targets - write to temp file
            target_file = output_file.parent / "nuclei_targets.txt"
            with open(target_file, "w") as f:
                f.write("\n".join(targets))
            cmd.extend(["-l", str(target_file)])

        # Output format
        cmd.extend(["-json", "-o", str(output_file)])

        # Tags
        tags = self.config.get("tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        # Exclude tags
        exclude_tags = self.config.get("exclude_tags", [])
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])

        # Severity
        severity = self.config.get("severity", [])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])

        # Rate limiting
        rate_limit = self.config.get("rate_limit", 150)
        cmd.extend(["-rate-limit", str(rate_limit)])

        bulk_size = self.config.get("bulk_size", 25)
        cmd.extend(["-bulk-size", str(bulk_size)])

        concurrency = self.config.get("concurrency", 25)
        cmd.extend(["-c", str(concurrency)])

        # Headless mode
        if self.config.get("headless", False):
            cmd.append("-headless")

        # Template directory
        template_dir = self.config.get("template_dir", "")
        if template_dir:
            cmd.extend(["-t", template_dir])

        # Additional args
        extra_args = self.config.get("extra_args", [])
        cmd.extend(extra_args)

        # Silent mode (reduce noise)
        cmd.append("-silent")

        # No color for parsing
        cmd.append("-no-color")

        return cmd

    def parse_output(self, output_file: Path, targets: list[str]) -> list[Finding]:
        findings = []

        if not output_file.exists():
            return findings

        with open(output_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    finding = self._parse_nuclei_result(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError as e:
                    # Skip malformed lines
                    continue

        return findings

    def _parse_nuclei_result(self, data: dict[str, Any]) -> Finding | None:
        """Parse a single Nuclei JSON result into a Finding."""
        try:
            info = data.get("info", {})
            matched = data.get("matched-at", data.get("host", ""))

            # Extract CVE IDs
            cve_ids = []
            for ref in info.get("reference", []):
                if ref.startswith("CVE-") or "cve-" in ref.lower():
                    cve_ids.append(ref.upper())
            # Also check tags
            for tag in info.get("tags", []):
                if tag.startswith("cve-"):
                    cve_ids.append(tag.upper())

            # Severity
            severity = info.get("severity", "info").upper()

            # CVSS
            cvss_vector = ""
            cvss_score = 0.0
            if "cvss-metrics" in info:
                cvss_vector = info["cvss-metrics"]
                # Could parse score from vector, but skip for now
            elif "classification" in info:
                classif = info["classification"]
                if "cvss-score" in classif:
                    cvss_score = float(classif["cvss-score"])
                if "cvss-vector" in classif:
                    cvss_vector = classif["cvss-vector"]

            # Target parsing
            target_host = ""
            target_port = 0
            target_protocol = ""
            target_url = matched

            if matched.startswith(("http://", "https://")):
                target_protocol = "http" if matched.startswith("http://") else "https"
                # Extract host:port from URL
                from urllib.parse import urlparse
                parsed = urlparse(matched)
                target_host = parsed.hostname or ""
                target_port = parsed.port or (443 if target_protocol == "https" else 80)
            else:
                # Assume host:port format
                if ":" in matched:
                    parts = matched.rsplit(":", 1)
                    target_host = parts[0]
                    try:
                        target_port = int(parts[1])
                    except ValueError:
                        target_port = 0
                else:
                    target_host = matched

            # Template ID
            template_id = data.get("template-id", data.get("template", ""))

            # Evidence
            evidence = {
                "matcher_name": data.get("matcher-name", ""),
                "extracted_results": data.get("extracted-results", []),
                "matched_at": matched,
                "curl_command": data.get("curl-command", ""),
            }

            request = data.get("request", "")
            response = data.get("response", "")

            return Finding(
                cve_ids=list(set(cve_ids)),
                title=info.get("name", template_id),
                description=info.get("description", ""),
                severity=severity,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                scanner="nuclei",
                template=template_id,
                tags=info.get("tags", []),
                target_host=target_host,
                target_port=target_port,
                target_protocol=target_protocol,
                target_url=target_url,
                evidence=evidence,
                request=request,
                response=response,
                remediation=info.get("remediation", ""),
                references=info.get("reference", []),
            )
        except Exception:
            return None

    def update_templates(self, template_dir: str | None = None) -> tuple[bool, str]:
        """Update Nuclei templates."""
        binary = self.find_binary()
        if not binary:
            return False, "Nuclei binary not found"

        try:
            cmd = [binary, "-update-templates"]
            if template_dir:
                cmd.extend(["-t", template_dir])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.returncode == 0, result.stdout or result.stderr
        except Exception as e:
            return False, str(e)