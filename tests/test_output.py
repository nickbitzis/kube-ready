import json

from helpers import container, healthy_set, report_for, workload

from kubeready.checks import REGISTRY
from kubeready.report import render_json, render_sarif, render_table


def bad_report():
    w = workload(
        containers=[container(image="nginx:latest")],
        replicas=1,
        annotations={"kubeready.io/ignore": "single-replica", "kubeready.io/ignore-reason": "Staging."},
    )
    return report_for(w)


def test_registry_has_at_least_twenty_checks_with_docs():
    assert len(REGISTRY) >= 20
    for c in REGISTRY.values():
        assert c.severity in ("error", "warning", "info")
        assert c.why.endswith(".") and c.fix.endswith(".")


def test_sarif_shape():
    sarif = json.loads(render_sarif(bad_report()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "kubeready"
    rule_ids = [r["id"] for r in driver["rules"]]
    assert set(rule_ids) == set(REGISTRY)
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert result["level"] in ("error", "warning", "note")
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
        assert "uri" in loc["artifactLocation"]


def test_sarif_levels_and_suppressions():
    results = json.loads(render_sarif(bad_report()))["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["image-tag"]["level"] == "error"
    assert by_rule["single-replica"]["suppressions"] == [{"kind": "inSource", "justification": "Staging."}]
    assert "suppressions" not in by_rule["image-tag"]


def test_json_output():
    data = json.loads(render_json(bad_report()))
    assert data["summary"]["error"] == 1
    assert data["summary"]["suppressed"] == 1
    first = data["findings"][0]
    assert {"check", "severity", "object", "file", "line", "message", "why", "fix"} <= set(first)
    assert data["scores"][0]["object"] == "Deployment shop/web"


def test_score_and_grade():
    score = bad_report().scores()[0]
    # 1 error (image-tag) and 1 warning (network-policy); single-replica is suppressed.
    assert score.counts == {"error": 1, "warning": 1, "info": 0}
    assert score.score == 80 and score.grade == "B"
    assert report_for(*healthy_set()).scores()[0].score == 100


def test_table_lists_findings_and_scores():
    text = render_table(bad_report(), explain=True)
    assert "image-tag" in text and "Workload scores" in text and "why:" in text
    assert "Suppressed" in text and "Staging." in text
