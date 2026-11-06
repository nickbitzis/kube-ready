from helpers import container, healthy_set, hpa, netpol, obj, pdb, run, service, workload


def test_single_replica():
    assert run(workload(replicas=1), check="single-replica") == ["runs 1 replica"]


def test_single_replica_default_when_field_missing():
    w = workload()
    del w["spec"]["replicas"]
    assert run(w, check="single-replica") == ["runs 1 replica"]


def test_single_replica_ok_when_hpa_min_is_two():
    assert run(workload(replicas=1), hpa(min_replicas=2), check="single-replica") == []


def test_single_replica_hpa_min_one_still_flagged():
    assert run(workload(replicas=3), hpa(min_replicas=1), check="single-replica") == [
        "runs 1 replica (HPA minReplicas)"
    ]


def test_pdb_missing_for_multi_replica():
    assert run(workload(replicas=3), check="pdb-missing") == ["3 replicas but no PodDisruptionBudget selects them"]


def test_pdb_present():
    assert run(workload(replicas=3), pdb(), check="pdb-missing") == []


def test_pdb_in_other_namespace_does_not_count():
    other = pdb()
    other["metadata"]["namespace"] = "other"
    assert run(workload(replicas=3), other, check="pdb-missing")


def test_pdb_not_needed_for_single_replica():
    assert run(workload(replicas=1), check="pdb-missing") == []


def test_pdb_selector_matches_nothing():
    assert run(workload(), pdb(labels={"app": "webb"}), check="pdb-selector")
    assert run(workload(), pdb(), check="pdb-selector") == []


def test_pdb_match_expressions():
    p = obj(
        "PodDisruptionBudget",
        "web",
        {"selector": {"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]}},
    )
    assert run(workload(), p, check="pdb-selector") == []


def test_spread_missing():
    assert run(workload(replicas=2), check="spread-missing")
    anti = {"affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": []}}}
    anti["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"] = [{"weight": 1}]
    assert run(workload(replicas=2, pod=anti), check="spread-missing") == []


def test_hpa_target_missing():
    assert run(hpa(target="ghost"), check="hpa-target-missing") == [
        "scaleTargetRef Deployment/ghost not found in namespace shop"
    ]
    assert run(workload(), hpa(), check="hpa-target-missing") == []


def test_hpa_target_without_cpu_request():
    c = container(resources={"requests": {"memory": "64Mi"}})
    msgs = run(workload(containers=[c]), hpa(), check="hpa-cpu-request")
    assert msgs == ["scales on CPU but Deployment shop/web container 'app' has no CPU request"]


def test_hpa_memory_only_does_not_need_cpu_request():
    c = container(resources={"requests": {"memory": "64Mi"}})
    metrics = [{"type": "Resource", "resource": {"name": "memory"}}]
    assert run(workload(containers=[c]), hpa(metrics=metrics), check="hpa-cpu-request") == []


def test_service_selector_no_match():
    assert run(workload(), service(selector={"app": "wbe"}), check="service-selector") == [
        "selector app=wbe matches no workload in namespace shop"
    ]
    assert run(workload(), service(), check="service-selector") == []


def test_service_without_selector_is_skipped():
    assert run(service(selector={}), check="service-selector") == []


def test_service_named_target_port_missing():
    svc = service(ports=[{"port": 80, "targetPort": "web"}])
    assert run(workload(), svc, check="service-target-port")
    assert run(workload(), service(), check="service-target-port") == []


def test_ingress_missing_service():
    ing = obj(
        "Ingress",
        "edge",
        {
            "rules": [
                {"http": {"paths": [{"path": "/", "backend": {"service": {"name": "nope", "port": {"number": 80}}}}]}}
            ]
        },
    )
    assert run(ing, check="ingress-backend") == ["backend Service 'nope' not found in namespace shop"]


def test_ingress_wrong_port_and_named_port():
    def ing(port):
        return obj("Ingress", "edge", {"defaultBackend": {"service": {"name": "web", "port": port}}})

    assert run(service(), ing({"number": 8080}), check="ingress-backend") == ["backend Service 'web' has no port 8080"]
    assert run(service(), ing({"number": 80}), check="ingress-backend") == []
    assert run(service(), ing({"name": "http"}), check="ingress-backend") == []


def test_network_policy_missing():
    assert run(workload(), check="network-policy") == ["no NetworkPolicy in namespace shop"]
    assert run(workload(), netpol(), check="network-policy") == []
    assert run(workload(), netpol(ns="other"), check="network-policy")


def test_config_ref_missing():
    c = container(
        envFrom=[{"configMapRef": {"name": "cfg"}}],
        env=[{"name": "PW", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}],
    )
    msgs = run(workload(containers=[c]), check="config-ref-missing")
    assert sorted(msgs) == [
        "references ConfigMap 'cfg', which is not in these manifests",
        "references Secret 'db', which is not in these manifests",
    ]
    assert run(workload(containers=[c]), obj("ConfigMap", "cfg"), obj("Secret", "db"), check="config-ref-missing") == []


def test_optional_config_ref_is_fine():
    c = container(envFrom=[{"configMapRef": {"name": "cfg", "optional": True}}])
    assert run(workload(containers=[c]), check="config-ref-missing") == []


def test_full_healthy_set_with_hpa_and_ingress():
    ing = obj("Ingress", "edge", {"defaultBackend": {"service": {"name": "web", "port": {"name": "http"}}}})
    assert run(*healthy_set(), hpa(), ing) == []
