"""Command-line entrypoint: `agent-tool-audit scan tools.json`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import ConfigError, ScanReport, scan_file

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_ICON = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED] ",
    "low": "[LOW] ",
    "info": "[INFO]",
}


def _print_report(report: ScanReport) -> None:
    print(f"\n{report.source}")
    print("=" * len(report.source))
    if not report.tools:
        print("No tool definitions found.")
        return
    for tool in sorted(report.tools, key=lambda t: t.score):
        print(f"\n{tool.name}  ->  grade {tool.grade} ({tool.score}/100)")
        if not tool.findings:
            print("   no issues found")
            continue
        ordered = sorted(tool.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
        for f in ordered:
            print(f"   {SEVERITY_ICON[f.severity]} {f.rule_id}: {f.message}")
    print(f"\nOverall: grade {report.overall_grade} ({report.overall_score}/100)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-tool-audit",
        description=(
            "Offline static analyzer for AI agent tool/function definitions "
            "(MCP tools/list responses, OpenAI-style function specs). Reads "
            "local JSON files only -- no network calls, ever."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan one or more tool-definition files")
    scan_p.add_argument("paths", nargs="+", help="Path(s) to JSON file(s)")
    scan_p.add_argument(
        "--fail-under",
        type=int,
        default=None,
        help="Exit non-zero if overall score of any file is below this value",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        worst_score = 100
        any_ok = False
        for raw in args.paths:
            path = Path(raw)
            if not path.is_file():
                print(f"\n{path}: file not found, skipping", file=sys.stderr)
                continue
            try:
                report = scan_file(path)
            except ConfigError as exc:
                print(f"\n{path}: {exc}", file=sys.stderr)
                continue
            _print_report(report)
            worst_score = min(worst_score, report.overall_score)
            any_ok = True

        if not any_ok:
            return 2
        if args.fail_under is not None and worst_score < args.fail_under:
            return 1
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
