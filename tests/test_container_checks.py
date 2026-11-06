import pytest
from helpers import container, healthy_set, run, workload


def test_healthy_set_has_no_findings():
    assert run(*healthy_set()) == []


def test_requests_missing():
    c = container(resources={"requests": {"memory": "64Mi"}, "limits": {"memory": "64Mi"}})
    assert run(workload(containers=[c]), check="container-requests") == ["container 'app' has no cpu request"]


def test_requests_present():
    assert run(workload(), check="container-requests") == []


def test_requests_checked_on_init_containers():
    init = container(name="migrate", resources={})
    msgs = run(workload(pod={"initContainers": [init]}), check="container-requests")
    assert msgs == ["container 'migrate' has no cpu or memory request"]


def test_memory_limit_missing():
    c = container(resources={"requests": {"cpu": "1", "memory": "1Gi"}})
    assert run(workload(containers=[c]), check="container-memory-limit")


def test_memory_limit_present():
    assert run(workload(), check="container-memory-limit") == []


def test_liveness_missing():
    c = container()
    del c["livenessProbe"]
    assert run(workload(containers=[c]), check="liveness-probe")


def test_liveness_not_required_for_cronjob():
    c = container()
    del c["livenessProbe"]
    del c["readinessProbe"]
    docs = (workload(kind="CronJob", containers=[c]),)
    assert run(*docs, check="liveness-probe") == []
    assert run(*docs, check="readiness-probe") == []


def test_readiness_missing():
    c = container()
    del c["readinessProbe"]
    assert run(workload(containers=[c]), check="readiness-probe")


def test_readiness_present():
    assert run(workload(), check="readiness-probe") == []


@pytest.mark.parametrize(
    "image,expected",
    [
        ("nginx", "has no tag"),
        ("nginx:latest", "uses the latest tag"),
        ("localhost:5000/team/app", "has no tag"),
    ],
)
def test_image_tag_bad(image, expected):
    msgs = run(workload(containers=[container(image=image)]), check="image-tag")
    assert len(msgs) == 1 and expected in msgs[0]


@pytest.mark.parametrize("image", ["nginx:1.27.1", "localhost:5000/team/app:2.0", "nginx@sha256:" + "a" * 64])
def test_image_tag_good(image):
    assert run(workload(containers=[container(image=image)]), check="image-tag") == []


def test_run_as_non_root_missing():
    c = container(securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True})
    assert run(workload(containers=[c]), check="run-as-non-root")


def test_run_as_non_root_from_pod_level():
    c = container(securityContext={"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True})
    w = workload(containers=[c], pod={"securityContext": {"runAsNonRoot": True}})
    assert run(w, check="run-as-non-root") == []


def test_run_as_non_root_container_override_false():
    c = container(securityContext={"runAsNonRoot": False})
    w = workload(containers=[c], pod={"securityContext": {"runAsNonRoot": True}})
    assert run(w, check="run-as-non-root")


def test_privileged():
    c = container(securityContext={"privileged": True, "runAsNonRoot": True})
    assert run(workload(containers=[c]), check="privileged") == ["container 'app' runs privileged"]
    assert run(workload(), check="privileged") == []


def test_privilege_escalation_default_is_flagged():
    c = container(securityContext={"runAsNonRoot": True, "readOnlyRootFilesystem": True})
    assert run(workload(containers=[c]), check="privilege-escalation")
    assert run(workload(), check="privilege-escalation") == []


def test_read_only_root_fs():
    c = container(securityContext={"runAsNonRoot": True, "allowPrivilegeEscalation": False})
    assert run(workload(containers=[c]), check="read-only-root-fs")
    assert run(workload(), check="read-only-root-fs") == []


def test_host_path():
    w = workload(pod={"volumes": [{"name": "dock", "hostPath": {"path": "/var/run/docker.sock"}}]})
    assert run(w, check="host-path") == ["volume 'dock' mounts hostPath '/var/run/docker.sock'"]
    w = workload(pod={"volumes": [{"name": "tmp", "emptyDir": {}}]})
    assert run(w, check="host-path") == []


def test_host_namespace():
    assert run(workload(pod={"hostPID": True}), check="host-namespace") == ["pod spec sets hostPID: true"]
    assert run(workload(), check="host-namespace") == []
