"""Configuration models using Pydantic for validation."""

from __future__ import annotations
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    """Normalized severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_nuclei(cls, value: str) -> SeverityLevel:
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(value.lower(), cls.INFO)

    @classmethod
    def from_trivy(cls, value: str) -> SeverityLevel:
        mapping = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
        }
        return mapping.get(value.upper(), cls.INFO)

    @classmethod
    def from_grype(cls, value: str) -> SeverityLevel:
        mapping = {
            "Critical": cls.CRITICAL,
            "High": cls.HIGH,
            "Medium": cls.MEDIUM,
            "Low": cls.LOW,
        }
        return mapping.get(value, cls.INFO)


class ScannerType(str, Enum):
    NUCLEI = "nuclei"
    NMAP = "nmap"
    TRIVY = "trivy"
    GRYPE = "grype"


class OutputFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"
    CSV = "csv"


class GlobalSettings(BaseModel):
    default_rate_limit: int = Field(default=30, ge=1, le=1000)
    max_concurrent_hosts: int = Field(default=10, ge=1, le=100)
    http_timeout: int = Field(default=15, ge=1, le=300)
    tcp_timeout: int = Field(default=10, ge=1, le=300)
    min_severity: SeverityLevel = Field(default=SeverityLevel.INFO)
    output_base_dir: str = Field(default="./results")
    enable_resume: bool = Field(default=True)
    verify_ssl: bool = Field(default=True)
    user_agent: str = Field(default="vuln_enum/1.0.0")


class NucleiConfig(BaseModel):
    enabled: bool = True
    binary_path: str = ""
    template_dir: str = ""
    default_tags: list[str] = Field(default_factory=lambda: [
        "cve", "vuln", "misconfig", "exposure", "takeover", "network", "ssl", "dns", "config"
    ])
    exclude_tags: list[str] = Field(default_factory=lambda: ["dos", "fuzz", "brute", "token-spray"])
    severity: list[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low", "info"])
    rate_limit: int = Field(default=150, ge=1, le=1000)
    bulk_size: int = Field(default=25, ge=1, le=100)
    concurrency: int = Field(default=25, ge=1, le=100)
    headless: bool = False
    extra_args: list[str] = Field(default_factory=list)


class NmapConfig(BaseModel):
    enabled: bool = True
    binary_path: str = ""
    script_categories: list[str] = Field(default_factory=lambda: ["vuln", "auth", "ssl", "default"])
    exclude_scripts: list[str] = Field(default_factory=lambda: [
        "http-brute", "ssh-brute", "snmp-brute", "smb-brute",
        "oracle-brute", "mysql-brute", "pgsql-brute"
    ])
    timing_template: int = Field(default=3, ge=0, le=5)
    max_retries: int = Field(default=2, ge=0, le=10)
    host_timeout: int = Field(default=30, ge=1, le=240)
    ports: str = ""
    extra_args: list[str] = Field(default_factory=lambda: ["-sV", "-sC"])


class TrivyConfig(BaseModel):
    enabled: bool = True
    binary_path: str = ""
    scan_types: list[str] = Field(default_factory=lambda: ["vuln", "config"])
    severity: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    format: str = "json"
    skip_db_update: bool = False
    timeout: int = Field(default=300, ge=30, le=3600)


class GrypeConfig(BaseModel):
    enabled: bool = False
    binary_path: str = ""
    severity: list[str] = Field(default_factory=lambda: ["Critical", "High", "Medium", "Low"])
    format: str = "json"


class ScannersConfig(BaseModel):
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    nmap: NmapConfig = Field(default_factory=NmapConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    grype: GrypeConfig = Field(default_factory=GrypeConfig)


class ScopeScannerOverrides(BaseModel):
    nuclei: NucleiConfig | None = None
    nmap: NmapConfig | None = None
    trivy: TrivyConfig | None = None
    grype: GrypeConfig | None = None


class Scope(BaseModel):
    name: str
    auth_ref: str
    description: str = ""
    targets: list[str] = Field(default_factory=list, min_length=1)
    exclusions: list[str] = Field(default_factory=list)
    profiles: list[str] = Field(default_factory=list, min_length=1)
    rate_limit: int | None = None
    max_concurrent_hosts: int | None = None
    scanners: ScopeScannerOverrides = Field(default_factory=ScopeScannerOverrides)

    @field_validator("targets", "exclusions")
    @classmethod
    def validate_not_empty(cls, v: list[str]) -> list[str]:
        return [item.strip() for item in v if item.strip()]


class ProfileScannerConfig(BaseModel):
    nuclei: NucleiConfig | None = None
    nmap: NmapConfig | None = None
    trivy: TrivyConfig | None = None
    grype: GrypeConfig | None = None


class Profile(BaseModel):
    description: str = ""
    scanners: list[ScannerType] = Field(default_factory=list)
    nuclei: NucleiConfig | None = None
    nmap: NmapConfig | None = None
    trivy: TrivyConfig | None = None
    grype: GrypeConfig | None = None


class Config(BaseModel):
    version: int = 1
    global_settings: GlobalSettings = Field(default_factory=GlobalSettings, alias="global")
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    scopes: list[Scope] = Field(default_factory=list, min_length=1)
    profiles: dict[str, Profile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scope_profiles_exist(self) -> Config:
        profile_names = set(self.profiles.keys())
        for scope in self.scopes:
            for profile in scope.profiles:
                if profile not in profile_names:
                    raise ValueError(f"Scope '{scope.name}' references unknown profile '{profile}'")
        return self


# Runtime scan configuration (merged global + scope + profile + CLI overrides)
class ScanConfig(BaseModel):
    scope: Scope
    global_settings: GlobalSettings
    scanners: ScannersConfig
    profiles: dict[str, Profile]
    cli_overrides: dict[str, Any] = Field(default_factory=dict)

    def get_effective_nuclei_config(self) -> NucleiConfig:
        base = self.scanners.nuclei.model_copy()
        for profile_name in self.scope.profiles:
            if profile := self.profiles.get(profile_name):
                if profile.nuclei:
                    base = self._merge_nuclei(base, profile.nuclei)
        if self.scope.scanners.nuclei:
            base = self._merge_nuclei(base, self.scope.scanners.nuclei)
        return base

    def get_effective_nmap_config(self) -> NmapConfig:
        base = self.scanners.nmap.model_copy()
        for profile_name in self.scope.profiles:
            if profile := self.profiles.get(profile_name):
                if profile.nmap:
                    base = self._merge_nmap(base, profile.nmap)
        if self.scope.scanners.nmap:
            base = self._merge_nmap(base, self.scope.scanners.nmap)
        return base

    def get_effective_trivy_config(self) -> TrivyConfig:
        base = self.scanners.trivy.model_copy()
        for profile_name in self.scope.profiles:
            if profile := self.profiles.get(profile_name):
                if profile.trivy:
                    base = self._merge_trivy(base, profile.trivy)
        if self.scope.scanners.trivy:
            base = self._merge_trivy(base, self.scope.scanners.trivy)
        return base

    def get_effective_grype_config(self) -> GrypeConfig:
        base = self.scanners.grype.model_copy()
        for profile_name in self.scope.profiles:
            if profile := self.profiles.get(profile_name):
                if profile.grype:
                    base = self._merge_grype(base, profile.grype)
        if self.scope.scanners.grype:
            base = self._merge_grype(base, self.scope.scanners.grype)
        return base

    def _merge_nuclei(self, base: NucleiConfig, override: NucleiConfig) -> NucleiConfig:
        data = base.model_dump()
        for key, value in override.model_dump(exclude_unset=True).items():
            if key in ("default_tags", "exclude_tags", "severity", "extra_args"):
                data[key] = list(set(data.get(key, []) + value))
            else:
                data[key] = value
        return NucleiConfig(**data)

    def _merge_nmap(self, base: NmapConfig, override: NmapConfig) -> NmapConfig:
        data = base.model_dump()
        for key, value in override.model_dump(exclude_unset=True).items():
            if key in ("script_categories", "exclude_scripts", "extra_args"):
                data[key] = list(set(data.get(key, []) + value))
            else:
                data[key] = value
        return NmapConfig(**data)

    def _merge_trivy(self, base: TrivyConfig, override: TrivyConfig) -> TrivyConfig:
        data = base.model_dump()
        for key, value in override.model_dump(exclude_unset=True).items():
            if key in ("scan_types", "severity"):
                data[key] = list(set(data.get(key, []) + value))
            else:
                data[key] = value
        return TrivyConfig(**data)

    def _merge_grype(self, base: GrypeConfig, override: GrypeConfig) -> GrypeConfig:
        data = base.model_dump()
        for key, value in override.model_dump(exclude_unset=True).items():
            if key in ("severity",):
                data[key] = list(set(data.get(key, []) + value))
            else:
                data[key] = value
        return GrypeConfig(**data)

    def get_enabled_scanners(self) -> list[ScannerType]:
        enabled = []
        for profile_name in self.scope.profiles:
            if profile := self.profiles.get(profile_name):
                enabled.extend(profile.scanners)
        return list(set(enabled))

    def get_rate_limit(self) -> int:
        return self.scope.rate_limit or self.global_settings.default_rate_limit

    def get_max_concurrent_hosts(self) -> int:
        return self.scope.max_concurrent_hosts or self.global_settings.max_concurrent_hosts

    def get_min_severity(self) -> SeverityLevel:
        return self.global_settings.min_severity

    def get_output_dir(self, scan_id: str) -> Path:
        base = Path(self.global_settings.output_base_dir)
        return base / self.scope.name / scan_id