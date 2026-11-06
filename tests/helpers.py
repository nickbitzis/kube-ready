"""Small builders so each test states only the field it cares about."""

from __future__ import annotations

import copy

from kubeready.engine import lint
from kubeready.model import K8sObject

NS = "shop"


def container(**overrides) -> dict:
    c = {
        "name": "app",
        "image": "registry.example.com/app:1.0.0",
        "ports": [{"name": "http", "containerPort": 8080}],
        "resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "64Mi"}},
        "readinessProbe": {"httpGet": {"path": "/ready", "port": "http"}},
        "livenessProbe": {"httpGet": {"path": "/healthz", "port": "http"}},
        "securityContext": {
            "runAsNonRoot": True,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
        },
    }
    c.update(overrides)
    return c


def workload(
    kind="Deployment", name="web", replicas=2, containers=None, labels=None, pod=None, annotations=None, ns=NS
) -> dict:
    labels = labels or {"app": name}
    pod_spec = {"containers": containers if containers is not None else [container()]}
    pod_spec.update(pod or {})
    template = {"metadata": {"labels": labels}, "spec": pod_spec}
    meta = {"name": name, "namespace": ns}
    if annotations:
        meta["annotations"] = annotations
    if kind == "CronJob":
        spec = {"schedule": "* * * * *", "jobTemplate": {"spec": {"template": template}}}
    else:
        spec = {"selector": {"matchLabels": labels}, "template": template}
        if kind in ("Deployment", "StatefulSet"):
            spec["replicas"] = replicas
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": spec}


def obj(kind, name, spec=None, ns=NS, **top) -> dict:
    d = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": ns}}
    if spec is not None:
        d["spec"] = spec
    d.update(top)
    return d


def service(name="web", selector=None, ports=None) -> dict:
    return obj(
        "Service",
        name,
        {
            "selector": selector if selector is not None else {"app": "web"},
            "ports": ports or [{"name": "http", "port": 80, "targetPort": "http"}],
        },
    )


def pdb(name="web", labels=None) -> dict:
    return obj(
        "PodDisruptionBudget", name, {"maxUnavailable": 1, "selector": {"matchLabels": labels or {"app": "web"}}}
    )


def hpa(target="web", kind="Deployment", min_replicas=2, metrics=None) -> dict:
    spec = {"scaleTargetRef": {"kind": kind, "name": target}, "minReplicas": min_replicas, "maxReplicas": 10}
    if metrics is not None:
        spec["metrics"] = metrics
    return obj("HorizontalPodAutoscaler", "web-hpa", spec)


def netpol(ns=NS) -> dict:
    return obj("NetworkPolicy", "default-deny", {"podSelector": {}}, ns=ns)


def run(*docs, check=None):
    """Lint the docs and return messages for one check (or all active findings)."""
    objects = [K8sObject(copy.deepcopy(d)) for d in docs]
    report = lint(objects)
    found = report.active if check is None else [f for f in report.active if f.check.id == check]
    return [f.message for f in found]


def report_for(*docs):
    return lint([K8sObject(copy.deepcopy(d)) for d in docs])


def healthy_set() -> list[dict]:
    """A web Deployment with everything it needs: zero findings."""
    return [
        workload(pod={"topologySpreadConstraints": [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname"}]}),
        service(),
        pdb(),
        netpol(),
    ]
