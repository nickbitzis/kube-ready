"""The checks. Each one is a small generator that yields a message per problem it finds.

A check declares the kinds it applies to, a severity, why it matters in production,
and how to fix it. Cross-object checks use the ObjectIndex to look at other objects.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .model import IGNORE_ANNOTATION, REASON_ANNOTATION, SCALABLE_KINDS, WORKLOAD_KINDS, K8sObject, ObjectIndex

SEVERITIES = ("info", "warning", "error")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES, start=1)}

CheckFn = Callable[[K8sObject, ObjectIndex], Iterator[str]]


@dataclass(frozen=True)
class Check:
    id: str
    severity: str
    kinds: frozenset[str] | None  # None means every kind
    why: str
    fix: str
    fn: CheckFn

    def applies_to(self, obj: K8sObject) -> bool:
        return self.kinds is None or obj.kind in self.kinds


REGISTRY: dict[str, Check] = {}


def check(id: str, severity: str, kinds, why: str, fix: str):
    assert severity in SEVERITIES, severity

    def register(fn: CheckFn) -> CheckFn:
        REGISTRY[id] = Check(id, severity, frozenset(kinds) if kinds else None, why, fix, fn)
        return fn

    return register


LONG_RUNNING = WORKLOAD_KINDS - {"CronJob", "Job"}


def _sc(container: dict) -> dict:
    return container.get("securityContext") or {}


# ---------------------------------------------------------------- containers


@check(
    "container-requests",
    "error",
    WORKLOAD_KINDS,
    "Without CPU and memory requests the scheduler packs pods blindly and they are first to be evicted.",
    "Set resources.requests.cpu and resources.requests.memory from observed usage.",
)
def container_requests(obj, idx):
    for c in obj.all_containers:
        requests = (c.get("resources") or {}).get("requests") or {}
        missing = [r for r in ("cpu", "memory") if r not in requests]
        if missing:
            yield f"container {c.get('name')!r} has no {' or '.join(missing)} request"


@check(
    "container-memory-limit",
    "warning",
    WORKLOAD_KINDS,
    "A container with no memory limit can grow until the node runs out and the kernel kills its neighbours.",
    "Set resources.limits.memory, usually equal to the memory request.",
)
def container_memory_limit(obj, idx):
    for c in obj.all_containers:
        if "memory" not in ((c.get("resources") or {}).get("limits") or {}):
            yield f"container {c.get('name')!r} has no memory limit"


@check(
    "liveness-probe",
    "warning",
    LONG_RUNNING,
    "Without a liveness probe a deadlocked process stays in rotation forever instead of being restarted.",
    "Add a livenessProbe on a cheap endpoint that only fails when a restart would help.",
)
def liveness_probe(obj, idx):
    for c in obj.containers:
        if "livenessProbe" not in c:
            yield f"container {c.get('name')!r} has no livenessProbe"


@check(
    "readiness-probe",
    "error",
    SCALABLE_KINDS,
    "Without a readiness probe traffic reaches pods before they can serve it, so every deploy drops requests.",
    "Add a readinessProbe that checks the app can serve, including its critical dependencies.",
)
def readiness_probe(obj, idx):
    for c in obj.containers:
        if "readinessProbe" not in c:
            yield f"container {c.get('name')!r} has no readinessProbe"


def image_tag(image: str) -> str | None:
    """Return the tag of an image reference, '@digest' if pinned by digest, or None if untagged."""
    if "@" in image:
        return "@digest"
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else None


@check(
    "image-tag",
    "error",
    WORKLOAD_KINDS,
    "A missing or 'latest' tag means two pods of the same Deployment can run different code, and rollback is a guess.",
    "Pin an immutable version tag or a sha256 digest.",
)
def image_tag_check(obj, idx):
    for c in obj.all_containers:
        image = str(c.get("image", ""))
        tag = image_tag(image)
        if tag is None:
            yield f"container {c.get('name')!r} image {image!r} has no tag"
        elif tag == "latest":
            yield f"container {c.get('name')!r} image {image!r} uses the latest tag"


@check(
    "run-as-non-root",
    "warning",
    WORKLOAD_KINDS,
    "A process running as root turns a container escape or a writable mount into root on the node.",
    "Set securityContext.runAsNonRoot: true (pod or container) and use an image with a non-root USER.",
)
def run_as_non_root(obj, idx):
    pod_sc = obj.pod_spec.get("securityContext") or {}
    for c in obj.all_containers:
        sc = _sc(c)
        non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if non_root is True or (isinstance(user, int) and user > 0):
            continue
        yield f"container {c.get('name')!r} may run as root (runAsNonRoot not set)"


@check(
    "privileged",
    "error",
    WORKLOAD_KINDS,
    "A privileged container has every capability and the host's devices, so it is effectively root on the node.",
    "Remove privileged: true and add only the specific capabilities the process needs.",
)
def privileged(obj, idx):
    for c in obj.all_containers:
        if _sc(c).get("privileged") is True:
            yield f"container {c.get('name')!r} runs privileged"


@check(
    "privilege-escalation",
    "warning",
    WORKLOAD_KINDS,
    "allowPrivilegeEscalation defaults to true, so a setuid binary can gain more rights than the pod was given.",
    "Set securityContext.allowPrivilegeEscalation: false on every container.",
)
def privilege_escalation(obj, idx):
    for c in obj.all_containers:
        if _sc(c).get("allowPrivilegeEscalation") is not False:
            yield f"container {c.get('name')!r} does not set allowPrivilegeEscalation: false"


@check(
    "read-only-root-fs",
    "warning",
    WORKLOAD_KINDS,
    "A writable root filesystem lets an attacker drop tools in the container and hides state lost on restart.",
    "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for paths that must be writable.",
)
def read_only_root_fs(obj, idx):
    for c in obj.all_containers:
        if _sc(c).get("readOnlyRootFilesystem") is not True:
            yield f"container {c.get('name')!r} has a writable root filesystem"


SENSITIVE_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIALS?)$", re.I)
SECRET_VALUE_PATTERNS = [
    ("an AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("a password assignment", re.compile(r"(password|passwd|pwd|secret|token)\s*[=:]\s*[^\s&;]+", re.I)),
    ("credentials in a URL", re.compile(r"://[^/\s:@]+:[^/\s@]+@")),
]


def _secret_reason(name: str, value: str) -> str | None:
    for label, pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            return label
    if SENSITIVE_NAME.search(name) and value and not value.startswith("$("):
        return "a credential-like name with a literal value"
    return None


@check(
    "plaintext-secret",
    "error",
    WORKLOAD_KINDS | {"ConfigMap"},
    "Credentials in env values or ConfigMaps are readable by anyone who can see the manifest, repo, or pod spec.",
    "Move the value into a Secret (or an external secret store) and reference it with valueFrom.secretKeyRef.",
)
def plaintext_secret(obj, idx):
    if obj.kind == "ConfigMap":
        for key, value in (obj.doc.get("data") or {}).items():
            reason = _secret_reason(str(key), str(value))
            if reason:
                yield f"data key {key!r} contains {reason}"
        return
    for c in obj.all_containers:
        for env in c.get("env") or []:
            if "value" not in env:
                continue
            reason = _secret_reason(str(env.get("name", "")), str(env.get("value") or ""))
            if reason:
                yield f"container {c.get('name')!r} env {env.get('name')!r} contains {reason}"


@check(
    "host-path",
    "warning",
    WORKLOAD_KINDS,
    "hostPath volumes tie the pod to one node's disk and can expose the node's filesystem to the container.",
    "Use a PersistentVolumeClaim, emptyDir, or a projected volume instead.",
)
def host_path(obj, idx):
    for vol in obj.pod_spec.get("volumes") or []:
        if "hostPath" in vol:
            yield f"volume {vol.get('name')!r} mounts hostPath {vol['hostPath'].get('path')!r}"


@check(
    "host-namespace",
    "error",
    WORKLOAD_KINDS,
    "Sharing the host network, PID, or IPC namespace removes the isolation between the pod and the node.",
    "Remove hostNetwork, hostPID, and hostIPC unless this is a node-level agent that truly needs them.",
)
def host_namespace(obj, idx):
    for field_name in ("hostNetwork", "hostPID", "hostIPC"):
        if obj.pod_spec.get(field_name) is True:
            yield f"pod spec sets {field_name}: true"


# ---------------------------------------------------------------- availability


@check(
    "single-replica",
    "warning",
    {"Deployment", "StatefulSet"},
    "One replica means every node drain, deploy, or crash is an outage.",
    "Run at least 2 replicas, or set an HPA with minReplicas >= 2.",
)
def single_replica(obj, idx):
    n = idx.effective_min_replicas(obj)
    if n is not None and n < 2:
        yield f"runs {n} replica" + (" (HPA minReplicas)" if idx.hpas_for(obj) else "")


@check(
    "pdb-missing",
    "warning",
    SCALABLE_KINDS,
    "Without a PodDisruptionBudget a node upgrade can evict every replica at once.",
    "Add a PodDisruptionBudget with minAvailable or maxUnavailable that selects these pods.",
)
def pdb_missing(obj, idx):
    n = idx.effective_min_replicas(obj) or 0
    if n >= 2 and not idx.pdbs_for(obj):
        yield f"{n} replicas but no PodDisruptionBudget selects them"


@check(
    "spread-missing",
    "info",
    SCALABLE_KINDS,
    "Without spread rules the scheduler may place every replica on one node or zone, so one failure takes them all.",
    "Add topologySpreadConstraints on kubernetes.io/hostname or topology.kubernetes.io/zone, or podAntiAffinity.",
)
def spread_missing(obj, idx):
    n = idx.effective_min_replicas(obj) or 0
    spec = obj.pod_spec
    if n >= 2 and not spec.get("topologySpreadConstraints") and not (spec.get("affinity") or {}).get("podAntiAffinity"):
        yield f"{n} replicas with no topologySpreadConstraints or podAntiAffinity"


# ---------------------------------------------------------------- cross-object


@check(
    "hpa-target-missing",
    "error",
    {"HorizontalPodAutoscaler"},
    "An HPA pointing at a workload that does not exist scales nothing, and nobody notices until load arrives.",
    "Fix scaleTargetRef kind and name so they match the workload.",
)
def hpa_target_missing(obj, idx):
    ref = obj.spec.get("scaleTargetRef") or {}
    if idx.get(str(ref.get("kind")), obj.namespace, str(ref.get("name"))) is None:
        yield f"scaleTargetRef {ref.get('kind')}/{ref.get('name')} not found in namespace {obj.namespace}"


def _hpa_uses_cpu(hpa: K8sObject) -> bool:
    if "targetCPUUtilizationPercentage" in hpa.spec:
        return True
    metrics = hpa.spec.get("metrics")
    if not metrics:
        return True  # the default metric is 80% CPU
    return any((m.get("resource") or m.get("containerResource") or {}).get("name") == "cpu" for m in metrics)


@check(
    "hpa-cpu-request",
    "error",
    {"HorizontalPodAutoscaler"},
    "CPU utilization is measured against the CPU request. With no request the HPA cannot compute it and never scales.",
    "Set resources.requests.cpu on every container of the target workload.",
)
def hpa_cpu_request(obj, idx):
    ref = obj.spec.get("scaleTargetRef") or {}
    target = idx.get(str(ref.get("kind")), obj.namespace, str(ref.get("name")))
    if target is None or not _hpa_uses_cpu(obj):
        return
    for c in target.containers:
        if "cpu" not in ((c.get("resources") or {}).get("requests") or {}):
            yield f"scales on CPU but {target.ref} container {c.get('name')!r} has no CPU request"


@check(
    "service-selector",
    "error",
    {"Service"},
    "A Service whose selector matches no pods has no endpoints, so every request to it fails.",
    "Make spec.selector match the labels in the workload's pod template.",
)
def service_selector(obj, idx):
    selector = obj.spec.get("selector") or {}
    if obj.spec.get("type") == "ExternalName" or not selector:
        return
    if not idx.workloads_for_service(obj):
        pairs = ",".join(f"{k}={v}" for k, v in selector.items())
        yield f"selector {pairs} matches no workload in namespace {obj.namespace}"


@check(
    "service-target-port",
    "error",
    {"Service"},
    "A named targetPort that no container declares leaves the Service with no endpoints on that port.",
    "Name the containerPort to match targetPort, or use the port number.",
)
def service_target_port(obj, idx):
    workloads = idx.workloads_for_service(obj)
    if not workloads:
        return
    names = {p.get("name") for w in workloads for c in w.containers for p in c.get("ports") or []}
    for port in obj.spec.get("ports") or []:
        target = port.get("targetPort")
        if isinstance(target, str) and target not in names:
            yield f"targetPort {target!r} is not a named containerPort in {', '.join(w.ref for w in workloads)}"


def _ingress_backends(obj: K8sObject) -> Iterator[tuple[str, object]]:
    """Yield (service name, port number or name) for every backend in an Ingress."""

    def one(backend: dict | None):
        if not backend:
            return None
        if "service" in backend:  # networking.k8s.io/v1
            svc = backend["service"]
            port = svc.get("port") or {}
            return svc.get("name"), port.get("number", port.get("name"))
        if "serviceName" in backend:  # older v1beta1 shape
            return backend["serviceName"], backend.get("servicePort")
        return None

    spec = obj.spec
    found = one(spec.get("defaultBackend") or spec.get("backend"))
    if found:
        yield found
    for rule in spec.get("rules") or []:
        for path in (rule.get("http") or {}).get("paths") or []:
            found = one(path.get("backend"))
            if found:
                yield found


@check(
    "ingress-backend",
    "error",
    {"Ingress"},
    "An Ingress backend pointing at a missing Service or port returns 503 for that route.",
    "Point the backend at an existing Service and one of its declared ports, by number or name.",
)
def ingress_backend(obj, idx):
    for name, port in _ingress_backends(obj):
        svc = idx.get("Service", obj.namespace, str(name))
        if svc is None:
            yield f"backend Service {name!r} not found in namespace {obj.namespace}"
            continue
        ports = svc.spec.get("ports") or []
        if port is not None and not any(port in (p.get("port"), p.get("name")) for p in ports):
            yield f"backend Service {name!r} has no port {port!r}"


@check(
    "pdb-selector",
    "warning",
    {"PodDisruptionBudget"},
    "A PodDisruptionBudget that selects no pods protects nothing, and its presence gives false confidence.",
    "Make spec.selector match the workload's pod template labels.",
)
def pdb_selector(obj, idx):
    if not idx.workloads_for_selector(obj.namespace, obj.spec.get("selector")):
        yield f"selector matches no workload in namespace {obj.namespace}"


@check(
    "network-policy",
    "warning",
    WORKLOAD_KINDS,
    "With no NetworkPolicy in the namespace, every pod in the cluster can reach these pods.",
    "Add a default-deny NetworkPolicy for the namespace, then allow the flows you need.",
)
def network_policy(obj, idx):
    if not idx.of_kind("NetworkPolicy", obj.namespace):
        yield f"no NetworkPolicy in namespace {obj.namespace}"


def _config_refs(obj: K8sObject) -> Iterator[tuple[str, str]]:
    """Yield (kind, name) for every non-optional ConfigMap or Secret the pod spec references."""
    spec = obj.pod_spec
    for vol in spec.get("volumes") or []:
        if "configMap" in vol and not vol["configMap"].get("optional"):
            yield "ConfigMap", vol["configMap"].get("name")
        if "secret" in vol and not vol["secret"].get("optional"):
            yield "Secret", vol["secret"].get("secretName")
    for c in obj.all_containers:
        for src in c.get("envFrom") or []:
            for key, kind in (("configMapRef", "ConfigMap"), ("secretRef", "Secret")):
                if key in src and not src[key].get("optional"):
                    yield kind, src[key].get("name")
        for env in c.get("env") or []:
            vf = env.get("valueFrom") or {}
            for key, kind in (("configMapKeyRef", "ConfigMap"), ("secretKeyRef", "Secret")):
                if key in vf and not vf[key].get("optional"):
                    yield kind, vf[key].get("name")


@check(
    "config-ref-missing",
    "info",
    WORKLOAD_KINDS,
    "A pod that references a missing ConfigMap or Secret stays in ContainerCreating, so the rollout stalls.",
    "Ship the ConfigMap or Secret with the workload, or mark the reference optional: true.",
)
def config_ref_missing(obj, idx):
    seen = set()
    for kind, name in _config_refs(obj):
        if (kind, name) not in seen and idx.get(kind, obj.namespace, str(name)) is None:
            seen.add((kind, name))
            yield f"references {kind} {name!r}, which is not in these manifests"


# ---------------------------------------------------------------- secrets and meta


@check(
    "secret-encoding",
    "error",
    {"Secret"},
    "Secret.data must be base64. A raw value is rejected by the API server, or decodes into garbage.",
    "Base64-encode values under data, or put plain values under stringData.",
)
def secret_encoding(obj, idx):
    for key, value in (obj.doc.get("data") or {}).items():
        try:
            base64.b64decode(str(value), validate=True)
        except (binascii.Error, ValueError):
            yield f"data key {key!r} is not valid base64"


@check(
    "ignore-needs-reason",
    "warning",
    None,
    "A suppression with no reason is impossible to review later, so it is not honoured.",
    f"Add a {REASON_ANNOTATION} annotation that says why the check does not apply.",
)
def ignore_needs_reason(obj, idx):
    if obj.annotations.get(IGNORE_ANNOTATION) and not str(obj.annotations.get(REASON_ANNOTATION, "")).strip():
        yield f"{IGNORE_ANNOTATION} is set without {REASON_ANNOTATION}, so it is ignored"
