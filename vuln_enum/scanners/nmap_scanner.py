"""Nmap scanner wrapper with NSE vuln scripts."""

from __future__ import annotations
import xml.etree.ElementTree as ET
import subprocess
from pathlib import Path
from typing import Any
from .base import BaseScanner, Finding, ScanResult


class NmapScanner(BaseScanner):
    """Wrapper for Nmap with vulnerability detection scripts."""

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def binary_name(self) -> str:
        return "nmap"

    def build_command(self, targets: list[str], output_file: Path) -> list[str]:
        binary = self.find_binary()
        if not binary:
            return []

        cmd = [binary]

        # Output format
        cmd.extend(["-oX", str(output_file)])

        # Target specification
        if len(targets) == 1 and not Path(targets[0]).exists():
            cmd.append(targets[0])
        else:
            # Multiple targets - write to temp file
            target_file = output_file.parent / "nmap_targets.txt"
            with open(target_file, "w") as f:
                f.write("\n".join(targets))
            cmd.extend(["-iL", str(target_file)])

        # Port specification
        ports = self.config.get("ports", "")
        if ports:
            cmd.extend(["-p", ports])

        # Service version detection
        cmd.append("-sV")

        # Default scripts
        cmd.append("-sC")

        # Vulnerability scripts
        script_categories = self.config.get("script_categories", ["vuln", "auth", "ssl", "default"])
        if script_categories:
            scripts = []
            for cat in script_categories:
                if cat == "vuln":
                    scripts.append("vuln")
                elif cat == "auth":
                    scripts.append("auth")
                elif cat == "ssl":
                    scripts.append("ssl-*")
                elif cat == "default":
                    scripts.append("default")
                elif cat.startswith("http-"):
                    scripts.append("http-*")
                elif cat.startswith("smb-"):
                    scripts.append("smb-*")
                elif cat.startswith("ldap-"):
                    scripts.append("ldap-*")
                elif cat.startswith("dns-"):
                    scripts.append("dns-*")
                elif cat.startswith("kerberos-"):
                    scripts.append("kerberos-*")
                else:
                    scripts.append(cat)
            cmd.extend(["--script", ",".join(scripts)])

        # Exclude scripts
        exclude_scripts = self.config.get("exclude_scripts", [])
        if exclude_scripts:
            cmd.extend(["--script-exclude", ",".join(exclude_scripts)])

        # Timing template
        timing = self.config.get("timing_template", 3)
        cmd.extend(["-T", str(timing)])

        # Host timeout
        host_timeout = self.config.get("host_timeout", 30)
        cmd.extend(["--host-timeout", f"{host_timeout}m"])

        # Max retries
        max_retries = self.config.get("max_retries", 2)
        cmd.extend(["--max-retries", str(max_retries)])

        # Additional args
        extra_args = self.config.get("extra_args", [])
        cmd.extend(extra_args)

        # No ping for faster scanning (assume hosts are up)
        cmd.append("-Pn")

        return cmd

    def parse_output(self, output_file: Path, targets: list[str]) -> list[Finding]:
        findings = []

        if not output_file.exists():
            return findings

        try:
            tree = ET.parse(output_file)
            root = tree.getroot()

            for host in root.findall("host"):
                # Get host address
                address_elem = host.find("address")
                target_host = address_elem.get("addr") if address_elem is not None else ""

                # Get hostnames
                hostnames = []
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hn in hostnames_elem.findall("hostname"):
                        hostnames.append(hn.get("name", ""))

                # Process ports
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue

                for port_elem in ports_elem.findall("port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "") if state_elem is not None else ""

                    if state != "open":
                        continue

                    # Service info
                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_version = ""
                    service_product = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        service_version = service_elem.get("version", "")
                        service_product = service_elem.get("product", "")

                    # Process scripts
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        output = script_elem.get("output", "")

                        if not output.strip():
                            continue

                        finding = self._parse_nse_script(
                            script_id, output, target_host, port_id, protocol,
                            service_name, service_product, service_version
                        )
                        if finding:
                            findings.append(finding)

        except ET.ParseError as e:
            pass  # Invalid XML, skip

        return findings

    def _parse_nse_script(
        self, script_id: str, output: str, host: str, port: int,
        protocol: str, service: str, product: str, version: str
    ) -> Finding | None:
        """Parse NSE script output into a Finding."""

        # Determine severity based on script and output
        severity = self._classify_severity(script_id, output)

        # Extract CVE IDs from output
        cve_ids = self._extract_cves(output)

        # Build title
        title = script_id.replace("-", " ").title()
        if cve_ids:
            title = f"{cve_ids[0]}: {title}"

        # Target URL
        target_url = f"{protocol}://{host}:{port}"

        # Service string
        service_str = service
        if product:
            service_str += f" ({product}"
            if version:
                service_str += f" {version}"
            service_str += ")"

        # Evidence
        evidence = {
            "script_id": script_id,
            "script_output": output[:5000],  # Limit size
            "service": service_str,
        }

        return Finding(
            cve_ids=cve_ids,
            title=title,
            description=output[:1000],
            severity=severity,
            scanner="nmap",
            template=script_id,
            tags=["network", "nse", script_id.split("-")[0] if "-" in script_id else "general"],
            target_host=host,
            target_port=port,
            target_protocol=protocol,
            target_service=service_str,
            target_url=target_url,
            evidence=evidence,
            request="",
            response=output[:2000],
            remediation=self._get_remediation(script_id),
            references=self._get_references(script_id, cve_ids),
        )

    def _classify_severity(self, script_id: str, output: str) -> str:
        """Classify severity based on script type and output."""
        output_lower = output.lower()

        # Critical indicators
        critical_keywords = [
            "remote code execution", "rce", "arbitrary code",
            "authentication bypass", "privilege escalation",
            "sql injection", "command injection",
            "backdoor", "malware", "botnet",
            "eternalblue", "bluekeep", "zerologon",
            "printnightmare", "proxyme",
        ]
        for kw in critical_keywords:
            if kw in output_lower:
                return "CRITICAL"

        # High indicators
        high_keywords = [
            "vulnerable", "exploit", "overflow", "traversal",
            "injection", "xss", "csrf", "ssrf",
            "disclosure", "enumeration", "anonymous",
            "default credentials", "weak password",
            "sslv2", "sslv3", "tls 1.0", "tls 1.1",
            "heartbleed", "poodle", "beast", "crime",
        ]
        for kw in high_keywords:
            if kw in output_lower:
                return "HIGH"

        # Medium indicators
        medium_keywords = [
            "information disclosure", "version disclosure",
            "directory listing", "backup file",
            "configuration issue", "misconfiguration",
            "weak cipher", "expired certificate",
            "self-signed", "hostname mismatch",
        ]
        for kw in medium_keywords:
            if kw in output_lower:
                return "MEDIUM"

        # Script-based classification
        script_lower = script_id.lower()
        if any(x in script_lower for x in ["vuln", "exploit", "backdoor", "malware"]):
            return "HIGH"
        if any(x in script_lower for x in ["auth", "brute", "default"]):
            return "MEDIUM"
        if any(x in script_lower for x in ["ssl", "tls", "cert"]):
            return "MEDIUM"
        if any(x in script_lower for x in ["discovery", "enum", "info", "version"]):
            return "INFO"

        return "LOW"

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE IDs from text."""
        import re
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))

    def _get_remediation(self, script_id: str) -> str:
        """Get remediation advice for script."""
        remediations = {
            "ssl-cert": "Use valid certificates from trusted CAs; automate renewal",
            "ssl-heartbleed": "Update OpenSSL to 1.0.1g+; revoke/reissue certificates",
            "ssl-poodle": "Disable SSLv3; use TLS 1.2+",
            "smb-vuln-ms17-010": "Apply MS17-010 patch; disable SMBv1",
            "smb-vuln-ms08-067": "Apply MS08-067 patch",
            "rdp-vuln-ms12-020": "Apply MS12-020 patch; enable NLA",
            "http-vuln-cve2021-41773": "Update Apache to 2.4.51+",
            "http-vuln-cve2021-44228": "Update Log4j to 2.17.0+",
            "http-vuln-cve2022-22965": "Update Spring Framework to 5.3.18+",
        }
        for key, value in remediations.items():
            if key in script_id:
                return value
        return "Review finding and apply vendor patches; follow hardening guides"

    def _get_references(self, script_id: str, cve_ids: list[str]) -> list[str]:
        """Get reference URLs for script."""
        refs = [f"https://nmap.org/nsedoc/scripts/{script_id}.html"]
        for cve in cve_ids:
            refs.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
        return refs