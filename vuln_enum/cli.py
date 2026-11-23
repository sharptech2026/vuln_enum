"""CLI entry point for vuln_enum."""

from __future__ import annotations
import sys
import argparse
from pathlib import Path
from typing import Any

from .orchestrator import run_scan, validate_scope
from .config.loader import ConfigLoader

__version__ = "1.0.0"
__author__ = "Security Research Team"
__tool_name__ = "vuln_enum"

BANNER = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  {__tool_name__.upper():<10} v{__version__:<8} │ Vulnerability Enumeration Framework      ║
║  Developed by: {__author__:<42}║
║  Purpose: Authorized vulnerability assessment & reporting                  ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚠️  ONLY scan targets you have explicit written authorization for.
    Unauthorized scanning is illegal in most jurisdictions.
"""


def print_banner():
    print(BANNER)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln_enum",
        description="Vulnerability enumeration framework for authorized assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vuln_enum scan --scope corp-external
  vuln_enum scan --scope corp-external --resume
  vuln_enum scan --scope corp-external --min-severity HIGH --formats json,html
  vuln_enum validate --scope corp-external
  vuln_enum list-scopes
  vuln_enum version

Environment Variables:
  VULN_ENUM_RATE_LIMIT       Global rate limit (req/s)
  VULN_ENUM_MAX_HOSTS        Max concurrent hosts
  VULN_ENUM_MIN_SEVERITY     Minimum severity to report
  VULN_ENUM_OUTPUT_DIR       Output directory base
  VULN_ENUM_NUCLEI_PATH      Path to nuclei binary
  VULN_ENUM_NMAP_PATH        Path to nmap binary
  VULN_ENUM_TRIVY_PATH       Path to trivy binary
  VULN_ENUM_GRYPE_PATH       Path to grype binary
"""
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", help="Path to configuration file (scopes.yaml)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner output")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument("--scope", "-s", required=True, help="Scope name from config")
    scan_parser.add_argument("--resume", "-r", action="store_true", help="Resume from checkpoint")
    scan_parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                            help="Minimum severity to report")
    scan_parser.add_argument("--formats", "-f", default="json,markdown,html,sarif,csv",
                            help="Output formats (comma-separated): json,markdown,html,sarif,csv")
    scan_parser.add_argument("--profiles", "-p", help="Override profiles (comma-separated)")
    scan_parser.add_argument("--targets", "-t", help="Override targets (comma-separated)")
    scan_parser.add_argument("--rate-limit", type=int, help="Override rate limit (req/s)")
    scan_parser.add_argument("--max-hosts", type=int, help="Override max concurrent hosts")
    scan_parser.add_argument("--no-nuclei", action="store_true", help="Disable nuclei scanner")
    scan_parser.add_argument("--no-nmap", action="store_true", help="Disable nmap scanner")
    scan_parser.add_argument("--no-trivy", action="store_true", help="Disable trivy scanner")
    scan_parser.add_argument("--no-grype", action="store_true", help="Disable grype scanner")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate scope configuration")
    validate_parser.add_argument("--scope", "-s", required=True, help="Scope name from config")

    # list-scopes command
    subparsers.add_parser("list-scopes", help="List available scopes")

    # version command
    subparsers.add_parser("version", help="Show version information")

    return parser


def build_cli_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Build CLI overrides dictionary from parsed arguments."""
    overrides = {}

    if args.min_severity:
        overrides["min_severity"] = args.min_severity
    if args.profiles:
        overrides["profiles"] = [p.strip() for p in args.profiles.split(",")]
    if args.targets:
        overrides["targets"] = [t.strip() for t in args.targets.split(",")]
    if args.rate_limit:
        overrides["rate_limit"] = args.rate_limit
    if args.max_hosts:
        overrides["max_hosts"] = args.max_hosts

    # Scanner disables
    disabled = []
    if args.no_nuclei:
        disabled.append("nuclei")
    if args.no_nmap:
        disabled.append("nmap")
    if args.no_trivy:
        disabled.append("trivy")
    if args.no_grype:
        disabled.append("grype")
    if disabled:
        overrides["disabled_scanners"] = disabled

    return overrides


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    try:
        if args.command == "scan":
            cli_overrides = build_cli_overrides(args)
            findings, results, stats = run_scan(
                scope_name=args.scope,
                config_path=args.config,
                resume=args.resume,
                cli_overrides=cli_overrides,
            )

            # Print summary
            print(f"\n{'='*60}")
            print(f"SCAN SUMMARY: {args.scope}")
            print(f"{'='*60}")
            print(f"Total findings: {len(findings)}")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = stats.by_severity.get(sev, 0)
                if count:
                    print(f"  {sev}: {count}")
            print(f"\nReports generated in: ./results/{args.scope}/scan-*/")
            return 0

        elif args.command == "validate":
            result = validate_scope(args.scope, args.config)
            print(f"\nValidation Result for scope '{args.scope}':")
            print(f"  Valid: {'✓' if result['valid'] else '✗'}")
            if result["issues"]:
                print("  Issues:")
                for issue in result["issues"]:
                    print(f"    - {issue}")
            if result["warnings"]:
                print("  Warnings:")
                for warn in result["warnings"]:
                    print(f"    - {warn}")
            print(f"  Targets: {len(result['targets'])}")
            print(f"  Exclusions: {len(result['exclusions'])}")
            print(f"  Profiles: {', '.join(result['profiles'])}")
            print(f"  Enabled scanners: {', '.join(result['enabled_scanners'])}")
            return 0 if result["valid"] else 1

        elif args.command == "list-scopes":
            loader = ConfigLoader(args.config)
            scopes = loader.list_scopes()
            print("\nAvailable scopes:")
            for scope in scopes:
                print(f"  - {scope}")
            return 0

        elif args.command == "version":
            print(f"{__tool_name__} v{__version__}")
            print(f"Developed by: {__author__}")
            return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        return 130
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())