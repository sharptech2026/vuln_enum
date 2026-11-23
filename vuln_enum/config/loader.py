"""Configuration loader with YAML support and environment variable overrides."""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml
from .models import Config, ScanConfig, Scope


class ConfigLoader:
    """Loads and merges configuration from YAML files and environment variables."""

    DEFAULT_CONFIG_FILES = [
        "config/scopes.yaml",
        "scopes.yaml",
        "./scopes.yaml",
        "~/.config/vuln_enum/scopes.yaml",
        "/etc/vuln_enum/scopes.yaml",
        # Package-internal config (when installed)
        "vuln_enum/config/scopes.yaml",
    ]

    def __init__(self, config_path: str | Path | None = None):
        self.config_path = Path(config_path) if config_path else None
        self._config: Config | None = None

    def load(self) -> Config:
        """Load configuration from file."""
        if self._config is not None:
            return self._config

        config_file = self._find_config_file()
        if not config_file:
            raise FileNotFoundError(
                "No configuration file found. Create 'config/scopes.yaml' or specify with --config"
            )

        with open(config_file, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not raw:
            raise ValueError("Configuration file is empty")

        # Apply environment variable overrides
        raw = self._apply_env_overrides(raw)

        self._config = Config(**raw)
        return self._config

    def _find_config_file(self) -> Path | None:
        """Find configuration file in standard locations."""
        if self.config_path and self.config_path.exists():
            return self.config_path

        for path_str in self.DEFAULT_CONFIG_FILES:
            path = Path(path_str).expanduser()
            if path.exists():
                return path

        return None

    def _apply_env_overrides(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            "VULN_ENUM_RATE_LIMIT": ("global_settings", "default_rate_limit", int),
            "VULN_ENUM_MAX_HOSTS": ("global_settings", "max_concurrent_hosts", int),
            "VULN_ENUM_MIN_SEVERITY": ("global_settings", "min_severity", str),
            "VULN_ENUM_OUTPUT_DIR": ("global_settings", "output_base_dir", str),
            "VULN_ENUM_VERIFY_SSL": ("global_settings", "verify_ssl", lambda x: x.lower() == "true"),
            "VULN_ENUM_NUCLEI_PATH": ("scanners", "nuclei", "binary_path", str),
            "VULN_ENUM_NMAP_PATH": ("scanners", "nmap", "binary_path", str),
            "VULN_ENUM_TRIVY_PATH": ("scanners", "trivy", "binary_path", str),
            "VULN_ENUM_GRYPE_PATH": ("scanners", "grype", "binary_path", str),
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is not None:
                target = raw
                for key in path[:-2]:
                    target = target.setdefault(key, {})
                converter = path[-1]
                target[path[-2]] = converter(value)

        return raw

    def get_scope(self, name: str) -> Scope:
        """Get a specific scope by name."""
        config = self.load()
        for scope in config.scopes:
            if scope.name == name:
                return scope
        available = [s.name for s in config.scopes]
        raise ValueError(f"Scope '{name}' not found. Available: {', '.join(available)}")

    def list_scopes(self) -> list[str]:
        """List all available scope names."""
        config = self.load()
        return [s.name for s in config.scopes]

    def build_scan_config(self, scope_name: str, cli_overrides: dict[str, Any] | None = None) -> ScanConfig:
        """Build a complete scan configuration for a scope."""
        config = self.load()
        scope = self.get_scope(scope_name)
        return ScanConfig(
            scope=scope,
            global_settings=config.global_settings,
            scanners=config.scanners,
            profiles=config.profiles,
            cli_overrides=cli_overrides or {},
        )

    def validate_scope(self, scope_name: str) -> dict[str, Any]:
        """Validate a scope configuration without running scans."""
        scope = self.get_scope(scope_name)
        config = self.load()

        issues = []
        warnings = []

        # Check targets
        if not scope.targets:
            issues.append("No targets defined")

        # Check profiles exist
        for profile_name in scope.profiles:
            if profile_name not in config.profiles:
                issues.append(f"Profile '{profile_name}' not found")

        # Check authorization reference
        if not scope.auth_ref:
            warnings.append("No auth_ref set - ensure you have written authorization")

        # Check scanner binaries (basic)
        for scanner_name in ["nuclei", "nmap", "trivy", "grype"]:
            scanner_config = getattr(config.scanners, scanner_name)
            if scanner_config.enabled and scanner_config.binary_path:
                if not Path(scanner_config.binary_path).exists():
                    warnings.append(f"{scanner_name} binary not found at {scanner_config.binary_path}")

        return {
            "scope": scope.name,
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "targets": scope.targets,
            "exclusions": scope.exclusions,
            "profiles": scope.profiles,
            "enabled_scanners": [s for s in ["nuclei", "nmap", "trivy", "grype"]
                                 if getattr(config.scanners, s).enabled],
        }