"""Base scanner interface and finding models."""

from __future__ import annotations
import hashlib
import json
import subprocess
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    """Normalized vulnerability finding."""
    # Core identification
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    cve_ids: list[str] = field(default_factory=list)
    title: str = ""
    description: str = ""
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_vector: str = ""
    cvss_score: float = 0.0

    # Source
    scanner: str = ""
    template: str = ""
    tags: list[str] = field(default_factory=list)

    # Target information
    target_host: str = ""
    target_port: int = 0
    target_protocol: str = ""
    target_service: str = ""
    target_url: str = ""

    # Evidence
    evidence: dict[str, Any] = field(default_factory=dict)
    matched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request: str = ""
    response: str = ""

    # Remediation
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Context
    scope: str = ""
    scan_id: str = ""

    def __post_init__(self):
        # Normalize severity
        self.severity = self.severity.upper()
        # Generate stable ID if not set
        if not self.id or self.id == str(uuid.uuid4())[:12]:
            self.id = self._generate_stable_id()

    def _generate_stable_id(self) -> str:
        """Generate stable ID based on key finding attributes."""
        key_parts = [
            self.scanner,
            self.template,
            self.target_host,
            str(self.target_port),
            self.title,
            ",".join(sorted(self.cve_ids)),
        ]
        key = "|".join(key_parts)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def matches_severity(self, min_severity: str) -> bool:
        """Check if finding meets minimum severity threshold."""
        order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return order.get(self.severity, 0) >= order.get(min_severity.upper(), 0)


@dataclass
class ScanResult:
    """Result of a scanner run."""
    scanner: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    targets_scanned: int = 0
    raw_output: str = ""
    command: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "targets_scanned": self.targets_scanned,
            "command": self.command,
        }


class BaseScanner(ABC):
    """Abstract base class for vulnerability scanners."""

    def __init__(self, config: dict[str, Any], audit_logger=None):
        self.config = config
        self.audit_logger = audit_logger
        self.binary_path = config.get("binary_path", "")
        self.enabled = config.get("enabled", True)

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name (e.g., 'nuclei', 'nmap')."""
        pass

    @property
    @abstractmethod
    def binary_name(self) -> str:
        """Binary name to search in PATH."""
        pass

    @abstractmethod
    def build_command(self, targets: list[str], output_file: Path) -> list[str]:
        """Build command line for scanning targets."""
        pass

    @abstractmethod
    def parse_output(self, output_file: Path, targets: list[str]) -> list[Finding]:
        """Parse scanner output into normalized findings."""
        pass

    def find_binary(self) -> str | None:
        """Find scanner binary in PATH or configured path."""
        if self.binary_path and Path(self.binary_path).exists():
            return self.binary_path

        # Search in PATH
        import shutil
        found = shutil.which(self.binary_name)
        if found:
            return found

        # Common locations
        common_paths = [
            Path.home() / "go" / "bin" / self.binary_name,
            Path("/usr/local/bin") / self.binary_name,
            Path("/opt") / self.binary_name / self.binary_name,
        ]
        for p in common_paths:
            if p.exists():
                return str(p)

        return None

    def run(self, targets: list[str], output_dir: Path, scan_id: str, scope: str) -> ScanResult:
        """Run scanner against targets."""
        if not self.enabled:
            return ScanResult(scanner=self.name, errors=["Scanner disabled in config"])

        binary = self.find_binary()
        if not binary:
            return ScanResult(scanner=self.name, errors=[f"{self.binary_name} not found in PATH"])

        output_file = output_dir / f"{self.name}_results.json"
        cmd = self.build_command(targets, output_file)
        cmd_str = " ".join(cmd)

        if self.audit_logger:
            config_hash = hashlib.sha256(cmd_str.encode()).hexdigest()[:16]
            self.audit_logger.log_scanner_start(self.name, targets, config_hash)

        start_time = datetime.now(timezone.utc)
        try:
            # Run with timeout
            timeout = self.config.get("timeout", 3600)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=output_dir,
            )
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()

            findings = []
            errors = []

            if result.returncode != 0 and result.returncode != 1:  # nuclei returns 1 when findings found
                errors.append(f"Exit code {result.returncode}: {result.stderr[:500]}")
            else:
                findings = self.parse_output(output_file, targets)
                for f in findings:
                    f.scope = scope
                    f.scan_id = scan_id

            if self.audit_logger:
                self.audit_logger.log_scanner_complete(
                    self.name, len(findings), duration, errors
                )

            return ScanResult(
                scanner=self.name,
                findings=findings,
                errors=errors,
                duration_seconds=duration,
                targets_scanned=len(targets),
                command=cmd_str,
            )

        except subprocess.TimeoutExpired:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            errors = [f"Timeout after {timeout}s"]
            if self.audit_logger:
                self.audit_logger.log_scanner_complete(self.name, 0, duration, errors)
            return ScanResult(scanner=self.name, errors=errors, duration_seconds=duration, targets_scanned=len(targets))
        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            errors = [f"Exception: {type(e).__name__}: {e}"]
            if self.audit_logger:
                self.audit_logger.log_scanner_complete(self.name, 0, duration, errors)
            return ScanResult(scanner=self.name, errors=errors, duration_seconds=duration, targets_scanned=len(targets))

    def verify_binary(self) -> tuple[bool, str]:
        """Verify binary exists and get version."""
        binary = self.find_binary()
        if not binary:
            return False, f"{self.binary_name} not found"
        try:
            result = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
            version = result.stdout.strip().split('\n')[0] if result.stdout else "unknown"
            return True, version
        except Exception as e:
            return False, f"Error: {e}"