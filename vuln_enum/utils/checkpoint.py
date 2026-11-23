"""Checkpoint/resume functionality for long-running scans."""

from __future__ import annotations
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Platform-specific locking
if sys.platform == "win32":
    import msvcrt
    fcntl = None
else:
    import fcntl
    msvcrt = None


class CheckpointManager:
    """Manages scan checkpoints for resume capability."""

    def __init__(self, output_dir: Path, scan_id: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = scan_id
        self.checkpoint_file = self.output_dir / "checkpoint.json"
        self.lock_file = self.output_dir / ".checkpoint.lock"
        self._lock_handle = None

    def _acquire_lock(self) -> bool:
        """Acquire file lock for checkpoint operations."""
        try:
            self._lock_handle = open(self.lock_file, "w")
            if sys.platform == "win32":
                msvcrt.locking(self._lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (IOError, OSError):
            if self._lock_handle:
                self._lock_handle.close()
                self._lock_handle = None
            return False

    def _release_lock(self) -> None:
        """Release file lock."""
        if self._lock_handle:
            if sys.platform == "win32":
                msvcrt.locking(self._lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()
            self._lock_handle = None

    def save(self, state: dict[str, Any]) -> bool:
        """Save checkpoint state atomically."""
        if not self._acquire_lock():
            return False
        try:
            # Write to temp file then atomic rename
            temp_file = self.checkpoint_file.with_suffix(".tmp")
            state["_meta"] = {
                "scan_id": self.scan_id,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "version": 1,
            }
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            os.replace(temp_file, self.checkpoint_file)
            return True
        finally:
            self._release_lock()

    def load(self) -> dict[str, Any] | None:
        """Load checkpoint state."""
        if not self.checkpoint_file.exists():
            return None
        if not self._acquire_lock():
            return None
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        finally:
            self._release_lock()

    def clear(self) -> bool:
        """Clear checkpoint (called on successful completion)."""
        if not self._acquire_lock():
            return False
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
            # Release lock BEFORE deleting lock file (Windows requirement)
            self._release_lock()
            if self.lock_file.exists():
                try:
                    self.lock_file.unlink()
                except OSError:
                    pass  # Best effort
            return True
        finally:
            # Ensure lock is released even if unlink failed
            if self._lock_handle:
                self._release_lock()

    def has_checkpoint(self) -> bool:
        """Check if a valid checkpoint exists."""
        return self.checkpoint_file.exists()

    def get_checkpoint_info(self) -> dict[str, Any] | None:
        """Get metadata about existing checkpoint without loading full state."""
        if not self.checkpoint_file.exists():
            return None
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            meta = data.get("_meta", {})
            return {
                "scan_id": meta.get("scan_id"),
                "saved_at": meta.get("saved_at"),
                "version": meta.get("version"),
                "scanners_completed": list(data.get("scanners_completed", [])),
                "targets_completed": data.get("targets_completed", 0),
                "total_targets": data.get("total_targets", 0),
            }
        except (json.JSONDecodeError, OSError):
            return None


class ScanState:
    """Represents the current state of a scan for checkpointing."""

    def __init__(self, scan_id: str, scope_name: str, total_targets: int):
        self.scan_id = scan_id
        self.scope_name = scope_name
        self.total_targets = total_targets
        self.targets_completed = 0
        self.scanners_completed: list[str] = []
        self.current_scanner: str | None = None
        self.current_target_index: int = 0
        self.findings: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scope_name": self.scope_name,
            "total_targets": self.total_targets,
            "targets_completed": self.targets_completed,
            "scanners_completed": self.scanners_completed,
            "current_scanner": self.current_scanner,
            "current_target_index": self.current_target_index,
            "findings": self.findings,
            "errors": self.errors,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanState:
        state = cls(
            scan_id=data["scan_id"],
            scope_name=data["scope_name"],
            total_targets=data["total_targets"],
        )
        state.targets_completed = data.get("targets_completed", 0)
        state.scanners_completed = data.get("scanners_completed", [])
        state.current_scanner = data.get("current_scanner")
        state.current_target_index = data.get("current_target_index", 0)
        state.findings = data.get("findings", [])
        state.errors = data.get("errors", [])
        state.started_at = data.get("started_at", state.started_at)
        state.updated_at = data.get("updated_at", state.updated_at)
        return state

    def mark_scanner_start(self, scanner: str) -> None:
        self.current_scanner = scanner
        self.current_target_index = 0
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_target_complete(self, target: str, findings: list[dict[str, Any]]) -> None:
        self.targets_completed += 1
        self.current_target_index = self.targets_completed
        self.findings.extend(findings)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_scanner_complete(self, scanner: str) -> None:
        if scanner not in self.scanners_completed:
            self.scanners_completed.append(scanner)
        self.current_scanner = None
        self.current_target_index = 0
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_error(self, error: str) -> None:
        self.errors.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": self.current_scanner,
            "error": error,
        })