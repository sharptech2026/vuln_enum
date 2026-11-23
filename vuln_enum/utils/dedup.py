"""Finding deduplication and merging logic."""

from __future__ import annotations
from collections import defaultdict
from typing import Any
from dataclasses import dataclass

from ..scanners.base import Finding


@dataclass
class DedupStats:
    """Statistics from deduplication."""
    original_count: int = 0
    deduped_count: int = 0
    merged_groups: int = 0
    by_scanner: dict[str, int] = None
    by_severity: dict[str, int] = None

    def __post_init__(self):
        if self.by_scanner is None:
            self.by_scanner = {}
        if self.by_severity is None:
            self.by_severity = {}


class FindingDeduplicator:
    """Deduplicates findings across scanners and targets."""

    def __init__(self, strategy: str = "smart"):
        """
        Initialize deduplicator.

        Strategies:
        - "exact": Exact match on all fields
        - "smart": Match on CVE + target + template (default)
        - "cve_only": Match only on CVE IDs
        - "target_template": Match on target + template
        """
        self.strategy = strategy

    def deduplicate(self, findings: list[Finding]) -> tuple[list[Finding], DedupStats]:
        """Deduplicate findings and return unique list with stats."""
        if not findings:
            return [], DedupStats()

        stats = DedupStats(original_count=len(findings))

        # Group findings by deduplication key
        groups = defaultdict(list)
        for finding in findings:
            key = self._get_dedup_key(finding)
            groups[key].append(finding)
            stats.by_scanner[finding.scanner] = stats.by_scanner.get(finding.scanner, 0) + 1
            stats.by_severity[finding.severity] = stats.by_severity.get(finding.severity, 0) + 1

        # Merge each group
        deduped = []
        for key, group in groups.items():
            if len(group) == 1:
                deduped.append(group[0])
            else:
                merged = self._merge_findings(group)
                deduped.append(merged)
                stats.merged_groups += 1

        stats.deduped_count = len(deduped)
        return deduped, stats

    def _get_dedup_key(self, finding: Finding) -> str:
        """Generate deduplication key based on strategy."""
        if self.strategy == "exact":
            # Use the finding's stable ID (hash of all key fields)
            return finding.id

        elif self.strategy == "cve_only":
            # Group by CVE IDs only
            cves = sorted(finding.cve_ids) if finding.cve_ids else ["NO_CVE"]
            return f"CVE:{','.join(cves)}"

        elif self.strategy == "target_template":
            # Group by target host:port + template
            return f"{finding.target_host}:{finding.target_port}|{finding.scanner}|{finding.template}"

        else:  # "smart" - default
            # Primary: CVE + target + template
            if finding.cve_ids:
                cves = sorted(finding.cve_ids)
                return f"CVE:{','.join(cves)}|{finding.target_host}:{finding.target_port}|{finding.template}"
            # Fallback: target + template + title similarity
            return f"{finding.target_host}:{finding.target_port}|{finding.scanner}|{finding.template}|{finding.title[:50]}"

    def _merge_findings(self, findings: list[Finding]) -> Finding:
        """Merge multiple findings into one, preserving best evidence."""
        if len(findings) == 1:
            return findings[0]

        # Sort by severity (highest first), then by scanner priority
        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        scanner_priority = {"nuclei": 4, "trivy": 3, "grype": 2, "nmap": 1}

        findings.sort(key=lambda f: (
            -severity_order.get(f.severity, 0),
            -scanner_priority.get(f.scanner, 0),
            -len(f.evidence),
            -len(f.cve_ids),
        ))

        primary = findings[0]

        # Merge CVE IDs (union)
        all_cves = set()
        for f in findings:
            all_cves.update(f.cve_ids)

        # Merge tags (union)
        all_tags = set()
        for f in findings:
            all_tags.update(f.tags)

        # Merge references (union)
        all_refs = set()
        for f in findings:
            all_refs.update(f.references)

        # Collect all scanners that found this
        scanners = list(set(f.scanner for f in findings))

        # Use most complete evidence
        best_evidence = max(findings, key=lambda f: len(str(f.evidence))).evidence
        best_evidence = dict(best_evidence)
        best_evidence["found_by_scanners"] = scanners
        best_evidence["finding_count"] = len(findings)

        # Use longest request/response
        best_request = max(findings, key=lambda f: len(f.request)).request
        best_response = max(findings, key=lambda f: len(f.response)).response

        # Use best remediation (longest)
        best_remediation = max(findings, key=lambda f: len(f.remediation)).remediation

        return Finding(
            id=primary.id,  # Keep primary's stable ID
            cve_ids=sorted(all_cves),
            title=primary.title,
            description=primary.description,
            severity=primary.severity,  # Highest severity
            cvss_vector=primary.cvss_vector,
            cvss_score=primary.cvss_score,
            scanner=",".join(sorted(scanners)),  # Multiple scanners
            template=primary.template,
            tags=sorted(all_tags),
            target_host=primary.target_host,
            target_port=primary.target_port,
            target_protocol=primary.target_protocol,
            target_service=primary.target_service,
            target_url=primary.target_url,
            evidence=best_evidence,
            request=best_request,
            response=best_response,
            remediation=best_remediation,
            references=sorted(all_refs),
            scope=primary.scope,
            scan_id=primary.scan_id,
        )


def deduplicate_findings(findings: list[Finding], strategy: str = "smart") -> tuple[list[Finding], DedupStats]:
    """Convenience function for deduplication."""
    deduplicator = FindingDeduplicator(strategy)
    return deduplicator.deduplicate(findings)