"""Render a Report as a human table, JSON, or SARIF 2.1.0."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .checks import REGISTRY
from .engine import Report

SARIF_LEVEL = {"error": "error", "warning": "warning", "info": "note"}
INFO_URI = "https://github.com/nickbitzis/kube-ready"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def summary_line(report: Report) -> str:
    c = report.counts()
    parts = [
        _plural(len(report.objects), "object"),
        f"in {_plural(len(report.files), 'file')}:",
        _plural(c["error"], "error") + ",",
        _plural(c["warning"], "warning") + ",",
        f"{c['info']} info",
    ]
    line = " ".join(parts)
    if report.suppressed:
        line += f" ({len(report.suppressed)} suppressed)"
    return line


def render_table(report: Report, explain: bool = False) -> str:
    lines = [summary_line(report), ""]
    active = report.active
    if active:
        rows = [(f.severity, f.check.id, f.obj.ref, f.message) for f in active]
        widths = [max(len(r[i]) for r in rows + [("SEVERITY", "CHECK", "OBJECT", "")]) for i in range(3)]
        header = ("SEVERITY", "CHECK", "OBJECT", "MESSAGE")
        fmt = "  ".join(f"{{:<{w}}}" for w in widths) + "  {}"
        lines.append(fmt.format(*header))
        for f, row in zip(active, rows, strict=True):
            lines.append(fmt.format(*row))
            if explain:
                pad = " " * (sum(widths) + 6)
                lines.append(f"{pad}why: {f.check.why}")
                lines.append(f"{pad}fix: {f.check.fix}")
        lines.append("")
    if report.suppressed:
        lines.append("Suppressed")
        for f in report.suppressed:
            lines.append(f"  {f.check.id:<22}  {f.obj.ref}  ({f.reason})")
        lines.append("")
    scores = [] if report.partial else report.scores()
    if scores:
        lines.append("Workload scores")
        width = max(len(s.obj.ref) for s in scores)
        for s in scores:
            c = s.counts
            lines.append(
                f"  {s.obj.ref:<{width}}  {s.score:>3}  {s.grade}"
                f"   ({c['error']} error, {c['warning']} warning, {c['info']} info)"
            )
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: Report) -> str:
    data = {
        "tool": "kubeready",
        "version": __version__,
        "summary": {**report.counts(), "suppressed": len(report.suppressed), "objects": len(report.objects)},
        "findings": [
            {
                "check": f.check.id,
                "severity": f.severity,
                "object": {"kind": f.obj.kind, "namespace": f.obj.namespace, "name": f.obj.name},
                "file": f.obj.path,
                "line": f.obj.line,
                "message": f.message,
                "why": f.check.why,
                "fix": f.check.fix,
                "suppressed": f.suppressed,
                **({"suppression_reason": f.reason} if f.suppressed else {}),
            }
            for f in report.findings
        ],
        "scores": [{"object": s.obj.ref, "score": s.score, "grade": s.grade, **s.counts} for s in report.scores()],
    }
    return json.dumps(data, indent=2) + "\n"


def _uri(path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(Path.cwd())
        except ValueError:
            pass
    return p.as_posix()


def render_sarif(report: Report) -> str:
    rule_ids = list(REGISTRY)
    rules = [
        {
            "id": c.id,
            "name": "".join(part.title() for part in c.id.split("-")),
            "shortDescription": {"text": c.why},
            "fullDescription": {"text": c.why},
            "help": {"text": f"{c.why} Fix: {c.fix}", "markdown": f"{c.why}\n\n**Fix:** {c.fix}"},
            "defaultConfiguration": {"level": SARIF_LEVEL[c.severity]},
            "properties": {"tags": ["kubernetes", "production-readiness"]},
        }
        for c in REGISTRY.values()
    ]
    results = []
    for f in report.findings:
        result = {
            "ruleId": f.check.id,
            "ruleIndex": rule_ids.index(f.check.id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.obj.ref}: {f.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(f.obj.path)},
                        "region": {"startLine": f.obj.line},
                    },
                    "logicalLocations": [{"name": f.obj.name, "fullyQualifiedName": f.obj.ref, "kind": "object"}],
                }
            ],
            "partialFingerprints": {"kubereadyObject/v1": f"{f.check.id}:{f.obj.ref}:{f.message}"},
        }
        if f.suppressed:
            result["suppressions"] = [{"kind": "inSource", "justification": f.reason}]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kubeready",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def render_checks() -> str:
    width = max(len(c) for c in REGISTRY)
    lines = []
    for c in REGISTRY.values():
        lines.append(f"{c.id:<{width}}  {c.severity:<7}  {c.why}")
    return "\n".join(lines) + "\n"
