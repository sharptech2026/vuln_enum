# vuln_enum

**Vulnerability Enumeration Framework** — A professional, cross-platform tool for authorized vulnerability assessments. Built for Kali Linux, Termux (Android), and Windows native.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  VULN_ENUM v1.0.0           │ Vulnerability Enumeration Framework           ║
║  Developed by: Security Research Team                                      ║
║  Purpose: Authorized vulnerability assessment & reporting                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## ⚠️ Legal Notice

**ONLY scan targets you have explicit written authorization for.** Unauthorized vulnerability scanning is illegal in most jurisdictions. This tool is designed for:
- Authorized penetration testing engagements
- Internal security assessments
- Bug bounty programs (within scope)
- Compliance auditing
- Research in controlled environments

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-scanner orchestration** | Nuclei, Nmap NSE, Trivy, Grype in one workflow |
| **Scope-driven** | YAML configuration with targets, exclusions, profiles, rate limits |
| **Cross-platform** | Runs on Kali, Termux (Android), Windows (native/WSL2) |
| **Deduplication** | Smart merging across scanners (CVE + target + template) |
| **Multiple outputs** | JSON, Markdown, HTML (interactive), SARIF, CSV |
| **Resume support** | Checkpoint/resume for long scans |
| **Audit logging** | Full JSONL audit trail with integrity verification |
| **Severity normalization** | Consistent CRITICAL/HIGH/MEDIUM/LOW/INFO across scanners |
| **Professional reports** | Executive summary + detailed findings with remediation |

---

## Installation

### Prerequisites

Install the external scanners (required):

```bash
# Nuclei (ProjectDiscovery)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Nmap
# Kali/Ubuntu/Debian: apt install nmap
# Windows: https://nmap.org/download.html
# Termux: pkg install nmap

# Trivy (Aqua Security)
# Linux: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# Windows: scoop install trivy
# Termux: pkg install trivy

# Grype (Anchore) - optional
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Install vuln_enum

```bash
# From source
git clone https://github.com/yourorg/vuln_enum
cd vuln_enum
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

### Verify installation

```bash
vuln_enum version
vuln_enum list-scopes
```

---

## Quick Start

### 1. Configure your scope

Edit `config/scopes.yaml` with your authorized targets:

```yaml
scopes:
  - name: "my-engagement"
    auth_ref: "CONTRACT-2024-001"
    description: "External assessment for Client Corp"
    targets:
      - "client.example.com"
      - "api.client.example.com"
      - "192.0.2.0/24"
    exclusions:
      - "192.0.2.10"  # Critical infrastructure
    profiles: ["web-full", "network-safe"]
```

### 2. Validate configuration

```bash
vuln_enum validate --scope my-engagement
```

### 3. Run scan

```bash
# Full scan
vuln_enum scan --scope my-engagement

# Quick scan (high/critical only)
vuln_enum scan --scope my-engagement --min-severity HIGH --profiles web-quick

# Resume interrupted scan
vuln_enum scan --scope my-engagement --resume
```

### 4. View results

```
results/my-engagement/scan-20241123-143000/
├── findings.json          # Machine-readable
├── report.md              # Markdown report
├── report.html            # Interactive HTML (filterable)
├── findings.sarif         # GitHub/CodeQL compatible
├── findings.csv           # Spreadsheet import
├── audit.log.jsonl        # Full audit trail
└── evidence/              # Raw scanner outputs
```

---

## Configuration

### Scope Structure

```yaml
scopes:
  - name: "unique-scope-name"
    auth_ref: "CONTRACT-REF"          # Your authorization reference
    description: "Human description"
    targets:                          # List of targets
      - "hostname"
      - "192.0.2.0/24"               # CIDR
      - "https://app.example.com"     # URL
    exclusions:                       # Excluded from scan
      - "192.0.2.10/32"
      - "legacy.example.com"
    profiles: ["web-full", "network-safe"]  # Profiles to run
    rate_limit: 30                    # Override global rate limit
    max_concurrent_hosts: 5           # Override global concurrency
    scanners:                         # Per-scope scanner overrides
      nuclei:
        rate_limit: 100
```

### Profiles

Pre-defined scanner combinations:

| Profile | Scanners | Use Case |
|---------|----------|----------|
| `web-full` | nuclei, nmap | Comprehensive web app scan |
| `web-quick` | nuclei | Fast web scan (critical/high only) |
| `network-safe` | nuclei, nmap | Non-intrusive network enumeration |
| `internal-full` | nuclei, nmap | Full internal network scan |
| `ad-enum` | nuclei, nmap | Active Directory focused |
| `config-checks` | nuclei | Hardening/misconfiguration checks |
| `container-cve` | trivy, grype | Container vulnerability scanning |
| `container-config` | trivy | Container hardening checks |

### Global Settings

```yaml
global:
  default_rate_limit: 30
  max_concurrent_hosts: 10
  min_severity: "INFO"
  output_base_dir: "./results"
  enable_resume: true
  verify_ssl: true
```

---

## CLI Reference

```
vuln_enum [OPTIONS] COMMAND [ARGS]...

Commands:
  scan        Run vulnerability scan
  validate    Validate scope configuration
  list-scopes List available scopes
  version     Show version information

Options:
  -c, --config PATH     Path to configuration file
  --no-banner           Suppress banner output
  -v, --version         Show version and exit
```

### Scan Command

```
vuln_enum scan --scope SCOPE [OPTIONS]

Options:
  -s, --scope TEXT           Scope name (required)
  -r, --resume               Resume from checkpoint
  --min-severity SEVERITY    CRITICAL|HIGH|MEDIUM|LOW|INFO
  -f, --formats FORMATS      Comma-separated: json,markdown,html,sarif,csv
  -p, --profiles TEXT        Override profiles (comma-separated)
  -t, --targets TEXT         Override targets (comma-separated)
  --rate-limit INT           Override rate limit (req/s)
  --max-hosts INT            Override max concurrent hosts
  --no-nuclei                Disable nuclei scanner
  --no-nmap                  Disable nmap scanner
  --no-trivy                 Disable trivy scanner
  --no-grype                 Disable grype scanner
```

---

## Output Formats

| Format | File | Use Case |
|--------|------|----------|
| JSON | `findings.json` | Automation, SIEM ingestion |
| Markdown | `report.md` | Documentation, sharing |
| HTML | `report.html` | Interactive review (filterable) |
| SARIF | `findings.sarif` | GitHub Code Scanning, CodeQL |
| CSV | `findings.csv` | Excel, spreadsheet analysis |

### HTML Report Features

- **Severity filtering** — Dropdown to show/hide by severity
- **Search** — Real-time text search across findings
- **Responsive** — Works on mobile/tablet
- **Expandable** — Click to expand/collapse details
- **Links** — CVE references open in new tab

---

## Audit & Compliance

Every scan produces a tamper-evident audit log (`audit.log.jsonl`):

```json
{
  "timestamp": "2024-11-23T14:30:00Z",
  "scan_id": "scan-20241123-143000",
  "scope": "my-engagement",
  "event": "scanner_complete",
  "data": {
    "scanner": "nuclei",
    "findings_count": 42,
    "duration_seconds": 125.3,
    "errors": []
  }
}
```

Verify integrity:
```bash
# Hash printed at scan completion
sha256sum results/my-engagement/scan-*/audit.log.jsonl
```

---

## Platform Notes

### Kali Linux
```bash
# All tools available via apt
apt update && apt install nmap nuclei trivy grype
pip install -e .
```

### Termux (Android)
```bash
pkg update && pkg install python nmap nuclei trivy
pip install -e .
# Note: grype not available in Termux repos; use trivy only
```

### Windows (Native)
```powershell
# Install via scoop/chocolatey
scoop install nmap trivy grype
# Nuclei: download from GitHub releases
# Python: from python.org or Microsoft Store
pip install -e .
```

### Windows (WSL2) — Recommended
```bash
# Use Kali/Ubuntu WSL distro
wsl --install -d Kali-Linux
# Then follow Kali instructions above
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VULN_ENUM_RATE_LIMIT` | Global rate limit (req/s) | 30 |
| `VULN_ENUM_MAX_HOSTS` | Max concurrent hosts | 10 |
| `VULN_ENUM_MIN_SEVERITY` | Minimum severity | INFO |
| `VULN_ENUM_OUTPUT_DIR` | Output base directory | ./results |
| `VULN_ENUM_VERIFY_SSL` | Verify SSL certificates | true |
| `VULN_ENUM_NUCLEI_PATH` | Nuclei binary path | auto-detect |
| `VULN_ENUM_NMAP_PATH` | Nmap binary path | auto-detect |
| `VULN_ENUM_TRIVY_PATH` | Trivy binary path | auto-detect |
| `VULN_ENUM_GRYPE_PATH` | Grype binary path | auto-detect |

---

## Example Workflows

### External Web Assessment
```bash
vuln_enum scan --scope corp-external \
  --profiles web-full,config-checks \
  --formats json,html,sarif \
  --min-severity MEDIUM
```

### Internal Network + AD
```bash
vuln_enum scan --scope corp-internal \
  --profiles internal-full,ad-enum \
  --rate-limit 50 \
  --max-hosts 20
```

### Container Registry Scan
```bash
vuln_enum scan --scope container-registry \
  --profiles container-cve,container-config \
  --formats json,csv
```

### CI/CD Integration (GitHub Actions)
```yaml
- name: Vulnerability Scan
  run: |
    vuln_enum scan --scope ${{ secrets.SCOPE }} \
      --formats sarif \
      --min-severity HIGH
  env:
    VULN_ENUM_NUCLEI_PATH: ${{ runner.temp }}/nuclei

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/${{ secrets.SCOPE }}/scan-*/findings.sarif
```

---

## Troubleshooting

### Scanner not found
```bash
# Check binary detection
vuln_enum validate --scope my-scope
# Look for "Warnings" section

# Or manually verify
which nuclei nmap trivy grype
```

### Scan too slow
- Increase `--rate-limit` (careful with target capacity)
- Use `--profiles web-quick` for faster web scans
- Reduce `--max-hosts` if target is rate-limiting

### Scan too fast / causing issues
- Decrease `--rate-limit`
- Add exclusions for sensitive systems
- Use `network-safe` profile (excludes brute/dos scripts)

### Resume not working
- Ensure `enable_resume: true` in config
- Check `results/scope/scan-*/checkpoint.json` exists
- Use `--resume` flag explicitly

---

## Architecture

```
vuln_enum/
├── config/              # Configuration loading & models
│   ├── loader.py        # YAML + env var loading
│   └── models.py        # Pydantic models
├── scanners/            # Scanner wrappers
│   ├── base.py          # Abstract base class
│   ├── nuclei_scanner.py
│   ├── nmap_scanner.py
│   ├── trivy_scanner.py
│   └── grype_scanner.py
├── utils/               # Utilities
│   ├── audit.py         # Audit logging
│   ├── checkpoint.py    # Resume/checkpoint
│   └── dedup.py         # Finding deduplication
├── reports/             # Report generation
│   └── generators.py    # Multi-format reports
├── vuln_enum/           # Main package
│   ├── orchestrator.py  # Scan workflow
│   └── cli.py           # CLI entry point
└── pyproject.toml       # Package config
```

---

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Setup

```bash
pip install -e ".[dev]"
pre-commit install
pytest
ruff check .
mypy vuln_enum
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for **authorized security testing only**. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse.

**Remember: Always have written authorization before scanning.**