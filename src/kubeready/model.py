"""Kubernetes objects as the linter sees them, plus a small index for cross-object checks."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "ReplicaSet"})
SCALABLE_KINDS = frozenset({"Deployment", "StatefulSet", "ReplicaSet"})

IGNORE_ANNOTATION = "kubeready.io/ignore"
REASON_ANNOTATION = "kubeready.io/ignore-reason"


@dataclass
class K8sObject:
    doc: dict[str, Any]
    path: str = "<memory>"
    line: int = 1

    @property
    def kind(self) -> str:
        return str(self.doc.get("kind", ""))

    @property
    def metadata(self) -> dict[str, Any]:
        return self.doc.get("metadata") or {}

    @property
    def name(self) -> str:
        return str(self.metadata.get("name", "<unnamed>"))

    @property
    def namespace(self) -> str:
        return str(self.metadata.get("namespace") or "default")

    @property
    def ref(self) -> str:
        return f"{self.kind} {self.namespace}/{self.name}"

    @property
    def spec(self) -> dict[str, Any]:
        return self.doc.get("spec") or {}

    @property
    def annotations(self) -> dict[str, str]:
        return self.metadata.get("annotations") or {}

    @property
    def is_workload(self) -> bool:
        return self.kind in WORKLOAD_KINDS

    @property
    def pod_template(self) -> dict[str, Any]:
        if self.kind == "CronJob":
            return ((self.spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
        if self.is_workload:
            return self.spec.get("template") or {}
        return {}

    @property
    def pod_spec(self) -> dict[str, Any]:
        return self.pod_template.get("spec") or {}

    @property
    def pod_labels(self) -> dict[str, str]:
        return (self.pod_template.get("metadata") or {}).get("labels") or {}

    @property
    def containers(self) -> list[dict[str, Any]]:
        return list(self.pod_spec.get("containers") or [])

    @property
    def all_containers(self) -> list[dict[str, Any]]:
        return list(self.pod_spec.get("initContainers") or []) + self.containers

    @property
    def replicas(self) -> int | None:
        """Declared replicas. Kubernetes defaults to 1 when the field is missing."""
        if self.kind not in SCALABLE_KINDS:
            return None
        value = self.spec.get("replicas", 1)
        return int(value) if isinstance(value, int) else 1


def selector_matches(selector: dict[str, Any] | None, labels: dict[str, str]) -> bool:
    """Evaluate a LabelSelector (matchLabels + matchExpressions). An empty selector matches everything."""
    if selector is None:
        return False
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def service_selector_matches(selector: dict[str, str], labels: dict[str, str]) -> bool:
    """Service selectors are plain equality maps."""
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


@dataclass
class ObjectIndex:
    """Lookup tables built once, so cross-object checks stay one or two lines each."""

    objects: list[K8sObject]
    _by_key: dict[tuple[str, str, str], K8sObject] = field(default_factory=dict)
    _by_kind: dict[str, list[K8sObject]] = field(default_factory=lambda: defaultdict(list))

    def __post_init__(self) -> None:
        for obj in self.objects:
            self._by_key[(obj.kind, obj.namespace, obj.name)] = obj
            self._by_kind[obj.kind].append(obj)

    def get(self, kind: str, namespace: str, name: str) -> K8sObject | None:
        return self._by_key.get((kind, namespace, name))

    def of_kind(self, kind: str, namespace: str | None = None) -> list[K8sObject]:
        items = self._by_kind.get(kind, [])
        return [o for o in items if namespace is None or o.namespace == namespace]

    def workloads(self, namespace: str | None = None) -> list[K8sObject]:
        return [o for o in self.objects if o.is_workload and (namespace is None or o.namespace == namespace)]

    def workloads_for_service(self, svc: K8sObject) -> list[K8sObject]:
        selector = svc.spec.get("selector") or {}
        return [w for w in self.workloads(svc.namespace) if service_selector_matches(selector, w.pod_labels)]

    def workloads_for_selector(self, namespace: str, selector: dict[str, Any] | None) -> list[K8sObject]:
        return [w for w in self.workloads(namespace) if selector_matches(selector, w.pod_labels)]

    def pdbs_for(self, workload: K8sObject) -> list[K8sObject]:
        return [
            p
            for p in self.of_kind("PodDisruptionBudget", workload.namespace)
            if selector_matches(p.spec.get("selector"), workload.pod_labels)
        ]

    def hpas_for(self, workload: K8sObject) -> list[K8sObject]:
        out = []
        for hpa in self.of_kind("HorizontalPodAutoscaler", workload.namespace):
            target = hpa.spec.get("scaleTargetRef") or {}
            if target.get("kind") == workload.kind and target.get("name") == workload.name:
                out.append(hpa)
        return out

    def effective_min_replicas(self, workload: K8sObject) -> int | None:
        """With an HPA, minReplicas is the floor. Without one, the declared replicas."""
        hpas = self.hpas_for(workload)
        if hpas:
            return max(int(h.spec.get("minReplicas", 1)) for h in hpas)
        return workload.replicas
