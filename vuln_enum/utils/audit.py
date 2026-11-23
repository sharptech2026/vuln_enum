"""Audit logging for scan activities."""

from __future__ import annotations
import json
import os
import platform
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib


class AuditLogger:
    """Structured audit logger for scan activities."""

    def __init__(self, output_dir: Path, scan_id: str, scope_name: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = scan_id
        self.scope_name = scope_name
        self.audit_file = self.output_dir / "audit.log.jsonl"
        self._session_id = str(uuid.uuid4())[:8]
        self._start_time = datetime.now(timezone.utc)
        self._tool_versions = self._detect_tool_versions()

        # Log session start
        self.log("session_start", {
            "scan_id": scan_id,
            "scope": scope_name,
            "session_id": self._session_id,
            "start_time": self._start_time.isoformat(),
            "tool_version": "1.0.0",
            "tool_name": "vuln_enum",
            "developed_by": "Security Research Team",
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "python": sys.version.split()[0],
            },
            "tool_versions": self._tool_versions,
            "pid": os.getpid(),
        })

    def _detect_tool_versions(self) -> dict[str, str]:
        """Detect versions of external tools."""
        versions = {}
        tools = {
            "nuclei": ["nuclei", "-version"],
            "nmap": ["nmap", "--version"],
            "trivy": ["trivy", "--version"],
            "grype": ["grype", "version"],
        }
        for name, cmd in tools.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Extract version from first line
                    first_line = result.stdout.strip().split('\n')[0]
                    versions[name] = first_line
                else:
                    versions[name] = f"error: {result.stderr.strip()[:100]}"
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                versions[name] = f"not found: {e}"
        return versions

    def log(self, event: str, data: dict[str, Any]) -> None:
        """Write an audit log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": self.scan_id,
            "scope": self.scope_name,
            "session_id": self._session_id,
            "event": event,
            "data": data,
        }
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def log_scan_start(self, config_summary: dict[str, Any]) -> None:
        """Log scan start with configuration summary."""
        self.log("scan_start", config_summary)

    def log_scanner_start(self, scanner: str, targets: list[str], config_hash: str) -> None:
        """Log individual scanner start."""
        self.log("scanner_start", {
            "scanner": scanner,
            "target_count": len(targets),
            "targets": targets[:10],  # First 10 only
            "config_hash": config_hash,
        })

    def log_scanner_complete(self, scanner: str, findings_count: int, duration_sec: float, errors: list[str]) -> None:
        """Log scanner completion."""
        self.log("scanner_complete", {
            "scanner": scanner,
            "findings_count": findings_count,
            "duration_seconds": round(duration_sec, 2),
            "errors": errors,
        })

    def log_finding(self, finding_id: str, severity: str, target: str, scanner: str) -> None:
        """Log individual finding (lightweight)."""
        self.log("finding", {
            "finding_id": finding_id,
            "severity": severity,
            "target": target,
            "scanner": scanner,
        })

    def log_dedup(self, original_count: int, deduped_count: int) -> None:
        """Log deduplication results."""
        self.log("deduplication", {
            "original_findings": original_count,
            "deduped_findings": deduped_count,
            "removed": original_count - deduped_count,
        })

    def log_report_generated(self, formats: list[str], output_files: list[str]) -> None:
        """Log report generation."""
        self.log("report_generated", {
            "formats": formats,
            "files": output_files,
        })

    def log_session_end(self, status: str, summary: dict[str, Any]) -> None:
        """Log session end."""
        end_time = datetime.now(timezone.utc)
        duration = (end_time - self._start_time).total_seconds()
        self.log("session_end", {
            "status": status,
            "duration_seconds": round(duration, 2),
            "end_time": end_time.isoformat(),
            "summary": summary,
        })

    def log_error(self, error: str, context: dict[str, Any] | None = None) -> None:
        """Log an error."""
        self.log("error", {
            "error": error,
            "context": context or {},
        })

    def get_audit_hash(self) -> str:
        """Compute SHA256 of audit log for integrity verification."""
        if not self.audit_file.exists():
            return ""
        hasher = hashlib.sha256()
        with open(self.audit_file, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()


class AuditReader:
    """Read and query audit logs."""

    def __init__(self, audit_file: Path):
        self.audit_file = Path(audit_file)

    def read_all(self) -> list[dict[str, Any]]:
        """Read all audit entries."""
        entries = []
        if not self.audit_file.exists():
            return entries
        with open(self.audit_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def get_session_summary(self) -> dict[str, Any] | None:
        """Get summary of the scan session."""
        entries = self.read_all()
        if not entries:
            return None

        start = next((e for e in entries if e["event"] == "session_start"), None)
        end = next((e for e in reversed(entries) if e["event"] == "session_end"), None)

        scanners = [e for e in entries if e["event"] == "scanner_complete"]
        findings = [e for e in entries if e["event"] == "finding"]

        return {
            "scan_id": start["scan_id"] if start else None,
            "scope": start["scope"] if start else None,
            "start_time": start["data"]["start_time"] if start else None,
            "end_time": end["data"]["end_time"] if end else None,
            "status": end["data"]["status"] if end else "incomplete",
            "duration_seconds": end["data"]["duration_seconds"] if end else None,
            "scanners_run": len(scanners),
            "total_findings": len(findings),
            "by_severity": self._count_by_severity(findings),
            "by_scanner": self._count_by_scanner(findings),
        }

    def _count_by_severity(self, findings: list[dict]) -> dict[str, int]:
        counts = {}
        for f in findings:
            sev = f["data"].get("severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_scanner(self, findings: list[dict]) -> dict[str, int]:
        counts = {}
        for f in findings:
            scanner = f["data"].get("scanner", "UNKNOWN")
            counts[scanner] = counts.get(scanner, 0) + 1
        return counts