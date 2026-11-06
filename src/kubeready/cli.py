"""Command line entry point: kubeready [PATH ...] [--format table|json|sarif] [--fail-on error]."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import REGISTRY
from .engine import lint
from .loader import LoadError, load_paths
from .report import render_checks, render_json, render_sarif, render_table

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kubeready",
        description="Lint Kubernetes manifests for production readiness.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    p.add_argument("-f", "--format", choices=["table", "json", "sarif"], default="table")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument(
        "--fail-on",
        choices=["error", "warning", "info", "none"],
        default="error",
        help="exit 1 if any finding is at or above this severity (default: error)",
    )
    p.add_argument("--only", help="comma-separated check ids to run")
    p.add_argument("--explain", action="store_true", help="show why and how to fix under each finding")
    p.add_argument("--list-checks", action="store_true", help="list every check and exit")
    p.add_argument("--version", action="version", version=f"kubeready {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        sys.stdout.write(render_checks())
        return EXIT_OK

    only = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}
        unknown = only - set(REGISTRY)
        if unknown:
            print(f"kubeready: unknown check id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return EXIT_USAGE

    try:
        objects, files = load_paths(args.paths)
    except LoadError as exc:
        print(f"kubeready: {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = lint(objects, files, only)
    if args.format == "json":
        text = render_json(report)
    elif args.format == "sarif":
        text = render_sarif(report)
    else:
        text = render_table(report, explain=args.explain)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return report.exit_code(args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
