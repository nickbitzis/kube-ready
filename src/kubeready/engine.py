"""Run the checks over an index, apply suppressions, and score workloads."""

from __future__ import annotations

from dataclasses import dataclass, field

from .checks import REGISTRY, SEVERITY_RANK, Check
from .model import IGNORE_ANNOTATION, REASON_ANNOTATION, K8sObject, ObjectIndex

PENALTY = {"error": 15, "warning": 5, "info": 1}
UNSUPPRESSIBLE = {"ignore-needs-reason"}


@dataclass
class Finding:
    check: Check
    obj: K8sObject
    message: str
    suppressed: bool = False
    reason: str | None = None

    @property
    def severity(self) -> str:
        return self.check.severity


@dataclass
class WorkloadScore:
    obj: K8sObject
    score: int
    grade: str
    counts: dict[str, int]


def grade(score: int) -> str:
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


@dataclass
class Report:
    objects: list[K8sObject]
    findings: list[Finding]
    files: list[str] = field(default_factory=list)
    partial: bool = False  # True when --only ran a subset, so scores are not comparable

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    def counts(self) -> dict[str, int]:
        out = {"error": 0, "warning": 0, "info": 0}
        for f in self.active:
            out[f.severity] += 1
        return out

    def scores(self) -> list[WorkloadScore]:
        result = []
        for obj in self.objects:
            if not obj.is_workload:
                continue
            counts = {"error": 0, "warning": 0, "info": 0}
            for f in self.active:
                if f.obj is obj:
                    counts[f.severity] += 1
            score = max(0, 100 - sum(PENALTY[s] * n for s, n in counts.items()))
            result.append(WorkloadScore(obj, score, grade(score), counts))
        return result

    def exit_code(self, fail_on: str) -> int:
        """1 if any active finding is at or above fail_on, else 0. fail_on='none' never fails."""
        if fail_on == "none":
            return 0
        threshold = SEVERITY_RANK[fail_on]
        return 1 if any(SEVERITY_RANK[f.severity] >= threshold for f in self.active) else 0


def suppressions(obj: K8sObject) -> tuple[set[str], str | None]:
    """Return (check ids to ignore, reason). Without a reason nothing is ignored."""
    raw = str(obj.annotations.get(IGNORE_ANNOTATION, ""))
    reason = str(obj.annotations.get(REASON_ANNOTATION, "")).strip()
    ids = {part.strip() for part in raw.split(",") if part.strip()}
    if not reason:
        return set(), None
    return ids - UNSUPPRESSIBLE, reason


def lint(objects: list[K8sObject], files: list[str] | None = None, only: set[str] | None = None) -> Report:
    index = ObjectIndex(objects)
    findings: list[Finding] = []
    for obj in objects:
        ignored, reason = suppressions(obj)
        for check in REGISTRY.values():
            if only and check.id not in only:
                continue
            if not check.applies_to(obj):
                continue
            for message in check.fn(obj, index):
                hit = check.id in ignored
                findings.append(Finding(check, obj, message, suppressed=hit, reason=reason if hit else None))
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.obj.path, f.obj.line, f.check.id))
    return Report(objects, findings, files or [], partial=bool(only))
