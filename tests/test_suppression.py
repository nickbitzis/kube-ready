from helpers import container, report_for, run, workload


def latest():
    return [container(image="nginx:latest")]


def test_suppression_with_reason():
    w = workload(
        containers=latest(),
        annotations={
            "kubeready.io/ignore": "image-tag, spread-missing",
            "kubeready.io/ignore-reason": "Vendor chart pins by digest at deploy time.",
        },
    )
    report = report_for(w)
    assert not [f for f in report.active if f.check.id in ("image-tag", "spread-missing")]
    suppressed = {f.check.id: f.reason for f in report.suppressed}
    assert suppressed["image-tag"] == "Vendor chart pins by digest at deploy time."


def test_suppression_without_reason_is_not_honoured():
    w = workload(containers=latest(), annotations={"kubeready.io/ignore": "image-tag"})
    assert run(w, check="image-tag")
    assert run(w, check="ignore-needs-reason")


def test_suppression_only_affects_named_checks():
    w = workload(
        containers=latest(),
        replicas=1,
        annotations={"kubeready.io/ignore": "single-replica", "kubeready.io/ignore-reason": "Dev only."},
    )
    assert run(w, check="single-replica") == []
    assert run(w, check="image-tag")


def test_blank_reason_counts_as_missing():
    w = workload(
        containers=latest(), annotations={"kubeready.io/ignore": "image-tag", "kubeready.io/ignore-reason": "   "}
    )
    assert run(w, check="image-tag")
    assert run(w, check="ignore-needs-reason")


def test_suppressed_findings_do_not_affect_exit_code():
    w = workload(
        containers=latest(), annotations={"kubeready.io/ignore": "image-tag", "kubeready.io/ignore-reason": "Reviewed."}
    )
    assert report_for(w).exit_code("error") == 0
