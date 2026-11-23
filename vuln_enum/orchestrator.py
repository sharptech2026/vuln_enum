"""Main scan orchestrator - coordinates scanners, deduplication, reporting."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config.loader import ConfigLoader
from .config.models import ScanConfig
from .scanners.nuclei_scanner import NucleiScanner
from .scanners.nmap_scanner import NmapScanner
from .scanners.trivy_scanner import TrivyScanner
from .scanners.grype_scanner import GrypeScanner
from .scanners.base import ScanResult
from .utils.audit import AuditLogger
from .utils.checkpoint import CheckpointManager, ScanState
from .utils.dedup import deduplicate_findings, DedupStats
from .reports.generators import generate_all_reports


class ScanOrchestrator:
    """Orchestrates vulnerability scanning workflow."""

    def __init__(self, scan_config: ScanConfig, scan_id: str | None = None, resume: bool = False):
        self.scan_config = scan_config
        self.scan_id = scan_id or f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.resume = resume
        self.output_dir = scan_config.get_output_dir(self.scan_id)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.audit_logger = AuditLogger(self.output_dir, self.scan_id, scan_config.scope.name)
        self.checkpoint_mgr = CheckpointManager(self.output_dir, self.scan_id)
        self.scan_state: ScanState | None = None

        # Initialize scanners
        self.scanners = self._init_scanners()

    def _init_scanners(self) -> dict[str, Any]:
        """Initialize enabled scanners with effective configs."""
        scanners = {}

        nuclei_config = self.scan_config.get_effective_nuclei_config()
        if nuclei_config.enabled:
            scanners["nuclei"] = NucleiScanner(nuclei_config.model_dump(), self.audit_logger)

        nmap_config = self.scan_config.get_effective_nmap_config()
        if nmap_config.enabled:
            scanners["nmap"] = NmapScanner(nmap_config.model_dump(), self.audit_logger)

        trivy_config = self.scan_config.get_effective_trivy_config()
        if trivy_config.enabled:
            scanners["trivy"] = TrivyScanner(trivy_config.model_dump(), self.audit_logger)

        grype_config = self.scan_config.get_effective_grype_config()
        if grype_config.enabled:
            scanners["grype"] = GrypeScanner(grype_config.model_dump(), self.audit_logger)

        return scanners

    def _prepare_targets(self) -> list[str]:
        """Expand and filter targets based on scope."""
        targets = []
        for target in self.scan_config.scope.targets:
            targets.append(target)

        # TODO: Implement CIDR expansion, exclusion filtering
        # For now, return as-is
        return targets

    def run(self) -> tuple[list, list[ScanResult], DedupStats]:
        """Execute complete scan workflow."""
        targets = self._prepare_targets()

        # Load or initialize scan state
        if self.resume and self.checkpoint_mgr.has_checkpoint():
            self.scan_state = ScanState.from_dict(self.checkpoint_mgr.load())
            print(f"Resuming scan {self.scan_id} from checkpoint...")
            print(f"  Completed scanners: {self.scan_state.scanners_completed}")
            print(f"  Targets completed: {self.scan_state.targets_completed}/{self.scan_state.total_targets}")
        else:
            self.scan_state = ScanState(
                scan_id=self.scan_id,
                scope_name=self.scan_config.scope.name,
                total_targets=len(targets),
            )

        # Log scan start
        self.audit_logger.log_scan_start({
            "scan_id": self.scan_id,
            "scope": self.scan_config.scope.name,
            "targets": targets,
            "profiles": self.scan_config.scope.profiles,
            "enabled_scanners": list(self.scanners.keys()),
            "global_settings": self.scan_config.global_settings.model_dump(),
        })

        all_findings = list(self.scan_state.findings) if self.scan_state.findings else []
        all_results = []
        all_errors = list(self.scan_state.errors) if self.scan_state.errors else []

        # Run each enabled scanner
        for scanner_name in self.scan_config.get_enabled_scanners():
            if scanner_name not in self.scanners:
                continue

            if scanner_name in self.scan_state.scanners_completed:
                print(f"Skipping {scanner_name} (already completed)")
                continue

            scanner = self.scanners[scanner_name]
            self.scan_state.mark_scanner_start(scanner_name)

            print(f"\n[+] Running {scanner_name} against {len(targets)} targets...")

            # Check if we have binary
            binary_ok, version = scanner.verify_binary()
            if not binary_ok:
                error_msg = f"{scanner_name}: {version}"
                print(f"  [-] {error_msg}")
                all_errors.append(error_msg)
                self.audit_logger.log_error(error_msg, {"scanner": scanner_name})
                self.scan_state.mark_scanner_complete(scanner_name)
                self._save_checkpoint()
                continue

            print(f"  [+] {scanner_name} version: {version}")

            # Run scanner
            result = scanner.run(targets, self.output_dir, self.scan_id, self.scan_config.scope.name)
            all_results.append(result)
            all_findings.extend(result.findings)
            all_errors.extend(result.errors)

            # Update state
            for f in result.findings:
                self.audit_logger.log_finding(f.id, f.severity, f.target_host, f.scanner)
            self.scan_state.mark_scanner_complete(scanner_name)
            self._save_checkpoint()

            print(f"  [+] {scanner_name} completed: {len(result.findings)} findings, {len(result.errors)} errors")

        # Deduplicate findings
        print("\n[+] Deduplicating findings...")
        deduped_findings, dedup_stats = deduplicate_findings(all_findings)
        self.audit_logger.log_dedup(dedup_stats.original_count, dedup_stats.deduped_count)
        print(f"  [+] {dedup_stats.original_count} -> {dedup_stats.deduped_count} findings ({dedup_stats.merged_groups} merged)")

        # Generate reports
        print("\n[+] Generating reports...")
        report_files = generate_all_reports(
            findings=deduped_findings,
            scan_results=all_results,
            scan_id=self.scan_id,
            scope_name=self.scan_config.scope.name,
            output_dir=self.output_dir,
            formats=["json", "markdown", "html", "sarif", "csv"],
        )
        self.audit_logger.log_report_generated(
            ["json", "markdown", "html", "sarif", "csv"],
            [str(f) for f in report_files]
        )

        for rf in report_files:
            print(f"  [+] Generated: {rf}")

        # Final summary
        summary = {
            "total_findings": len(deduped_findings),
            "by_severity": dedup_stats.by_severity,
            "by_scanner": dedup_stats.by_scanner,
            "scanners_run": list(self.scanners.keys()),
            "scan_duration_seconds": sum(r.duration_seconds for r in all_results),
            "report_files": [str(f) for f in report_files],
            "audit_log": str(self.audit_logger.audit_file),
            "audit_hash": self.audit_logger.get_audit_hash(),
        }

        self.audit_logger.log_session_end("completed", summary)
        self.checkpoint_mgr.clear()

        print(f"\n[+] Scan completed: {self.scan_id}")
        print(f"    Findings: {summary['total_findings']}")
        print(f"    Output: {self.output_dir}")
        print(f"    Audit: {self.audit_logger.audit_file}")

        return deduped_findings, all_results, dedup_stats

    def _save_checkpoint(self) -> None:
        """Save current scan state."""
        if self.scan_state:
            self.checkpoint_mgr.save(self.scan_state.to_dict())

    def validate_only(self) -> dict[str, Any]:
        """Validate configuration without running scans."""
        loader = ConfigLoader()
        return loader.validate_scope(self.scan_config.scope.name)


def run_scan(scope_name: str, config_path: str | None = None, resume: bool = False,
             cli_overrides: dict[str, Any] | None = None) -> tuple[list, list[ScanResult], DedupStats]:
    """Convenience function to run a complete scan."""
    loader = ConfigLoader(config_path)
    scan_config = loader.build_scan_config(scope_name, cli_overrides or {})
    orchestrator = ScanOrchestrator(scan_config, resume=resume)
    return orchestrator.run()


def validate_scope(scope_name: str, config_path: str | None = None) -> dict[str, Any]:
    """Validate a scope configuration."""
    loader = ConfigLoader(config_path)
    return loader.validate_scope(scope_name)