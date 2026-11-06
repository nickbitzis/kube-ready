# kubeready

A production-readiness linter for Kubernetes manifests, in the spirit of kube-score and Polaris but small enough to read in one sitting. It parses multi-document YAML, runs 25 checks (each with a severity, a one-line reason it matters in production, and a fix hint), and prints a table, JSON, or SARIF for GitHub code scanning. The interesting part is the cross-object checks: a Service whose selector matches no pods, an HPA scaling on CPU for a Deployment with no CPU request, an Ingress pointing at a port the Service does not have.

One dependency (PyYAML). 83 tests.

## Why

Most Kubernetes outages are not exotic. A Service selector has a typo, so it has zero endpoints. An HPA cannot compute CPU utilization because the pods have no CPU request, so it never scales. A three-replica Deployment has no PodDisruptionBudget, so a routine node upgrade evicts all three at once. Every one of these is visible in the YAML before it ships, but only if something looks at more than one object at a time. Single-object schema validation (kubeval, `kubectl --dry-run`) passes all of them.

kubeready runs in CI and in pre-commit, fails the build above a severity you choose, and posts findings to the GitHub Security tab through SARIF, so reviewers see them inline on the pull request.

## Quick start

```
uv sync --python 3.12
uv run kubeready examples/bad          # exit 1
uv run kubeready examples/fixed        # exit 0
uv run kubeready examples/bad --explain --only service-selector,hpa-cpu-request
uv run kubeready examples/bad --format sarif --output kubeready.sarif --fail-on none
uv run kubeready --list-checks
```

## Before and after

`examples/bad/` is a deliberately broken "checkout" app for a made-up shop: an API Deployment, a payments Deployment, a cleanup CronJob, a log agent DaemonSet, plus their Service, HPA, Ingress, PDB, ConfigMap, and Secret. Real output:

```
$ uv run kubeready examples/bad
11 objects in 3 files: 18 errors, 27 warnings, 1 info

SEVERITY  CHECK                   OBJECT                                     MESSAGE
error     container-requests      Deployment shop/checkout-api               container 'api' has no cpu request
error     image-tag               Deployment shop/checkout-api               container 'api' image 'registry.example.com/shop/checkout-api:latest' uses the latest tag
error     plaintext-secret        Deployment shop/checkout-api               container 'api' env 'DB_PASSWORD' contains a credential-like name with a literal value
error     plaintext-secret        Deployment shop/checkout-api               container 'api' env 'DATABASE_URL' contains credentials in a URL
error     plaintext-secret        Deployment shop/checkout-api               container 'api' env 'AWS_ACCESS_KEY_ID' contains an AWS access key id
error     readiness-probe         Deployment shop/checkout-api               container 'api' has no readinessProbe
error     service-selector        Service shop/checkout-api                  selector app=checkout matches no workload in namespace shop
error     hpa-cpu-request         HorizontalPodAutoscaler shop/checkout-api  scales on CPU but Deployment shop/checkout-api container 'api' has no CPU request
error     ingress-backend         Ingress shop/shop                          backend Service 'checkout' not found in namespace shop
error     ingress-backend         Ingress shop/shop                          backend Service 'payments' has no port 8080
error     container-requests      CronJob shop/cart-cleanup                  container 'cleanup' has no cpu or memory request
error     image-tag               CronJob shop/cart-cleanup                  container 'cleanup' image 'registry.example.com/shop/cart-cleanup:latest' uses the latest tag
error     container-requests      DaemonSet shop/log-agent                   container 'agent' has no cpu or memory request
error     host-namespace          DaemonSet shop/log-agent                   pod spec sets hostNetwork: true
error     privileged              DaemonSet shop/log-agent                   container 'agent' runs privileged
error     image-tag               Deployment shop/payments                   container 'payments' image 'registry.example.com/shop/payments' has no tag
error     secret-encoding         Secret shop/payments-keys                  data key 'api_key' is not valid base64
error     plaintext-secret        ConfigMap shop/checkout-config             data key 'SMTP_PASSWORD' contains a credential-like name with a literal value
warning   container-memory-limit  Deployment shop/checkout-api               container 'api' has no memory limit
warning   liveness-probe          Deployment shop/checkout-api               container 'api' has no livenessProbe
warning   network-policy          Deployment shop/checkout-api               no NetworkPolicy in namespace shop
warning   pdb-missing             Deployment shop/checkout-api               3 replicas but no PodDisruptionBudget selects them
warning   privilege-escalation    Deployment shop/checkout-api               container 'api' does not set allowPrivilegeEscalation: false
warning   read-only-root-fs       Deployment shop/checkout-api               container 'api' has a writable root filesystem
warning   run-as-non-root         Deployment shop/checkout-api               container 'api' may run as root (runAsNonRoot not set)
warning   container-memory-limit  CronJob shop/cart-cleanup                  container 'cleanup' has no memory limit
warning   network-policy          CronJob shop/cart-cleanup                  no NetworkPolicy in namespace shop
warning   privilege-escalation    CronJob shop/cart-cleanup                  container 'cleanup' does not set allowPrivilegeEscalation: false
warning   read-only-root-fs       CronJob shop/cart-cleanup                  container 'cleanup' has a writable root filesystem
warning   run-as-non-root         CronJob shop/cart-cleanup                  container 'cleanup' may run as root (runAsNonRoot not set)
warning   container-memory-limit  DaemonSet shop/log-agent                   container 'agent' has no memory limit
warning   host-path               DaemonSet shop/log-agent                   volume 'varlog' mounts hostPath '/var/log'
warning   ignore-needs-reason     DaemonSet shop/log-agent                   kubeready.io/ignore is set without kubeready.io/ignore-reason, so it is ignored
warning   liveness-probe          DaemonSet shop/log-agent                   container 'agent' has no livenessProbe
warning   network-policy          DaemonSet shop/log-agent                   no NetworkPolicy in namespace shop
warning   privilege-escalation    DaemonSet shop/log-agent                   container 'agent' does not set allowPrivilegeEscalation: false
warning   read-only-root-fs       DaemonSet shop/log-agent                   container 'agent' has a writable root filesystem
warning   run-as-non-root         DaemonSet shop/log-agent                   container 'agent' may run as root (runAsNonRoot not set)
warning   liveness-probe          Deployment shop/payments                   container 'payments' has no livenessProbe
warning   network-policy          Deployment shop/payments                   no NetworkPolicy in namespace shop
warning   privilege-escalation    Deployment shop/payments                   container 'payments' does not set allowPrivilegeEscalation: false
warning   read-only-root-fs       Deployment shop/payments                   container 'payments' has a writable root filesystem
warning   run-as-non-root         Deployment shop/payments                   container 'payments' may run as root (runAsNonRoot not set)
warning   single-replica          Deployment shop/payments                   runs 1 replica
warning   pdb-selector            PodDisruptionBudget shop/payments          selector matches no workload in namespace shop
info      spread-missing          Deployment shop/checkout-api               3 replicas with no topologySpreadConstraints or podAntiAffinity

Workload scores
  Deployment shop/checkout-api    0  F   (6 error, 7 warning, 1 info)
  CronJob shop/cart-cleanup      45  D   (2 error, 5 warning, 0 info)
  DaemonSet shop/log-agent       15  F   (3 error, 8 warning, 0 info)
  Deployment shop/payments       55  D   (1 error, 6 warning, 0 info)
```

`examples/fixed/` is the same app after review: pinned images, requests and limits, probes, a hardened security context, credentials moved to Secrets, PDBs, zone spread, and a default-deny NetworkPolicy. The log agent keeps its hostPath mount on purpose, with a reviewed suppression:

```
$ uv run kubeready examples/fixed
15 objects in 4 files: 0 errors, 0 warnings, 0 info (1 suppressed)

Suppressed
  host-path               DaemonSet shop/log-agent  (Node log agent: reads /var/log read-only by design.)

Workload scores
  Deployment shop/checkout-api  100  A   (0 error, 0 warning, 0 info)
  CronJob shop/cart-cleanup     100  A   (0 error, 0 warning, 0 info)
  DaemonSet shop/log-agent      100  A   (0 error, 0 warning, 0 info)
  Deployment shop/payments      100  A   (0 error, 0 warning, 0 info)
```

With `--explain`, each finding also says why it matters and how to fix it. `--only` limits the run to some checks (scores are hidden, since they would not be comparable):

```
$ uv run kubeready examples/bad --explain --only service-selector,hpa-cpu-request
11 objects in 3 files: 2 errors, 0 warnings, 0 info

SEVERITY  CHECK             OBJECT                                     MESSAGE
error     service-selector  Service shop/checkout-api                  selector app=checkout matches no workload in namespace shop
                                                                       why: A Service whose selector matches no pods has no endpoints, so every request to it fails.
                                                                       fix: Make spec.selector match the labels in the workload's pod template.
error     hpa-cpu-request   HorizontalPodAutoscaler shop/checkout-api  scales on CPU but Deployment shop/checkout-api container 'api' has no CPU request
                                                                       why: CPU utilization is measured against the CPU request. With no request the HPA cannot compute it and never scales.
                                                                       fix: Set resources.requests.cpu on every container of the target workload.
```

## Checks

```
container-requests      error    Without CPU and memory requests the scheduler packs pods blindly and they are first to be evicted.
container-memory-limit  warning  A container with no memory limit can grow until the node runs out and the kernel kills its neighbours.
liveness-probe          warning  Without a liveness probe a deadlocked process stays in rotation forever instead of being restarted.
readiness-probe         error    Without a readiness probe traffic reaches pods before they can serve it, so every deploy drops requests.
image-tag               error    A missing or 'latest' tag means two pods of the same Deployment can run different code, and rollback is a guess.
run-as-non-root         warning  A process running as root turns a container escape or a writable mount into root on the node.
privileged              error    A privileged container has every capability and the host's devices, so it is effectively root on the node.
privilege-escalation    warning  allowPrivilegeEscalation defaults to true, so a setuid binary can gain more rights than the pod was given.
read-only-root-fs       warning  A writable root filesystem lets an attacker drop tools in the container and hides state lost on restart.
plaintext-secret        error    Credentials in env values or ConfigMaps are readable by anyone who can see the manifest, repo, or pod spec.
host-path               warning  hostPath volumes tie the pod to one node's disk and can expose the node's filesystem to the container.
host-namespace          error    Sharing the host network, PID, or IPC namespace removes the isolation between the pod and the node.
single-replica          warning  One replica means every node drain, deploy, or crash is an outage.
pdb-missing             warning  Without a PodDisruptionBudget a node upgrade can evict every replica at once.
spread-missing          info     Without spread rules the scheduler may place every replica on one node or zone, so one failure takes them all.
hpa-target-missing      error    An HPA pointing at a workload that does not exist scales nothing, and nobody notices until load arrives.
hpa-cpu-request         error    CPU utilization is measured against the CPU request. With no request the HPA cannot compute it and never scales.
service-selector        error    A Service whose selector matches no pods has no endpoints, so every request to it fails.
service-target-port     error    A named targetPort that no container declares leaves the Service with no endpoints on that port.
ingress-backend         error    An Ingress backend pointing at a missing Service or port returns 503 for that route.
pdb-selector            warning  A PodDisruptionBudget that selects no pods protects nothing, and its presence gives false confidence.
network-policy          warning  With no NetworkPolicy in the namespace, every pod in the cluster can reach these pods.
config-ref-missing      info     A pod that references a missing ConfigMap or Secret stays in ContainerCreating, so the rollout stalls.
secret-encoding         error    Secret.data must be base64. A raw value is rejected by the API server, or decodes into garbage.
ignore-needs-reason     warning  A suppression with no reason is impossible to review later, so it is not honoured.
```

Cross-object checks: `single-replica` and `pdb-missing` (both read the HPA's `minReplicas` when one targets the workload), `hpa-target-missing`, `hpa-cpu-request`, `service-selector`, `service-target-port`, `ingress-backend`, `pdb-selector`, `network-policy`, `config-ref-missing`.

## Architecture

```
  files / dirs
       |
  loader.py       split on ---, keep the start line of each document, skip non-Kubernetes YAML
       |
  K8sObject list
       |
  ObjectIndex     by (kind, namespace, name) and by kind; selector matching; HPA and PDB lookups
       |
  engine.lint     run every registered check on every object it applies to,
       |          apply kubeready.io/ignore suppressions, sort by severity
       |
  Report          counts, per-workload score, exit code for --fail-on
       |
  report.py       table | JSON | SARIF 2.1.0
```

A check is one decorated generator in `src/kubeready/checks.py`:

```python
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
        ...
        yield f"selector {pairs} matches no workload in namespace {obj.namespace}"
```

Adding a check is one function. It shows up in the table, JSON, SARIF rules, and `--list-checks` with no other changes.

## Suppressions

Some findings are correct and still not a problem: a node log agent needs a hostPath mount. Suppress a check on one object with two annotations:

```yaml
metadata:
  annotations:
    kubeready.io/ignore: host-path,spread-missing
    kubeready.io/ignore-reason: "Node log agent: reads /var/log read-only by design."
```

The reason is required. An ignore with no reason (or a blank one) is not honoured and raises its own `ignore-needs-reason` warning, so every suppression in the repo can be reviewed later. Suppressed findings still appear in the table under "Suppressed", in JSON with `suppressed: true`, and in SARIF as `inSource` suppressions with the reason as the justification.

## Scores and exit codes

Each workload starts at 100 and loses 15 per error, 5 per warning, and 1 per info, with a floor of 0. Grades: A at 90 or more, B at 75, C at 60, D at 40, F below.

| Exit code | Meaning |
|---|---|
| 0 | No active finding at or above `--fail-on` (default `error`). |
| 1 | At least one active finding at or above `--fail-on`. |
| 2 | Usage or parse error: missing file, invalid YAML, unknown check id. |

`--fail-on none` always exits 0, which is how the SARIF step runs so the upload happens even when the build should fail.

## Using it in CI

### GitHub code scanning (SARIF)

SARIF is a standard JSON format for static analysis results. When a workflow uploads a SARIF file with `github/codeql-action/upload-sarif`, GitHub shows each finding in the repo's Security tab and as an annotation on the pull request diff, with the rule's help text. kubeready writes one SARIF rule per check (severity mapped to `error`, `warning`, or `note`), and one result per finding with the file and the line where the object starts. Code scanning must be enabled for the repo: it is free for public repos and needs GitHub Advanced Security on private ones.

### Reusable action

`action.yml` at the repo root is a composite action. Other repos can use it like this:

```yaml
jobs:
  kubeready:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - id: kubeready
        uses: nickbitzis/kube-ready@main
        with:
          paths: deploy/
          fail-on: error
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.kubeready.outputs.sarif-file }}
          category: kubeready
```

This repo's own `.github/workflows/ci.yml` has three jobs: `test` (ruff and pytest), `scan` (runs the local action on `examples/fixed` and uploads the SARIF), and `docker` (builds the image and checks the bad example exits 1).

### pre-commit

```yaml
repos:
  - repo: https://github.com/nickbitzis/kube-ready
    rev: main
    hooks:
      - id: kubeready
        args: [deploy/, --fail-on, error]
```

The hook scans a folder rather than only the changed files, because cross-object checks need every manifest. A change to a Deployment's labels can break a Service in another file.

### Docker

```
docker build -t kubeready .
docker run --rm -v "$PWD/examples:/work:ro" kubeready fixed
```

The image is a two-stage build on `python:3.12-slim` and runs as a non-root user. Docker is not needed to use the tool; the Dockerfile is built and run in CI.

## Tests

83 tests (`uv run pytest -q`), all passing:

- Every check has a positive and a negative case, including init containers, digests and registry ports in image names, pod-level versus container-level security context, and `$(VAR)` references that are not secrets.
- Cross-object: selectors with `matchLabels` and `matchExpressions`, objects in other namespaces, HPA `minReplicas` overriding declared replicas, memory-only HPAs, named and numbered Ingress ports, optional ConfigMap references.
- Suppression with a reason, without one, with a blank one, and its effect on exit codes.
- SARIF shape: version, one rule per check, `ruleIndex` pointing at the right rule, levels, line numbers, suppressions.
- CLI: exit codes 0, 1, and 2, `--fail-on` thresholds, `--only`, file output, and both example sets.
- Loader: multi-document line numbers, `kind: List`, non-Kubernetes YAML skipped, parse errors with a location.

`make lint` runs ruff check and ruff format.

## Production notes

- Helm charts and Kustomize overlays are not valid YAML until rendered. Run `helm template` or `kustomize build` first and pipe the result to a file, which also means kubeready checks what actually gets applied.
- Line numbers point at the start of each object. Pointing at the exact field would need a YAML parser that keeps positions for every node (ruamel.yaml), which is the next step if findings get noisy on large files.
- Checks are hard-coded. At scale, teams want a policy file that turns checks on or off and changes severities per namespace or per environment, so staging can run with one replica without a suppression on every object.
- Cross-object checks only see the manifests passed in. A Service in this repo that selects pods deployed from another repo will be flagged. The fix is a live-cluster mode that adds `kubectl get -o yaml` output to the index.
- The secret patterns catch common mistakes, not determined ones. A real pipeline should also run a dedicated scanner (gitleaks, trufflehog) on the whole repo.
- Admission control (Kyverno, Gatekeeper) is the enforcement layer in the cluster. kubeready is the earlier, cheaper layer that catches the same problems at review time.

## License

MIT. See [LICENSE](LICENSE).
