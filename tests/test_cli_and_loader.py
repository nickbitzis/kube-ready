import json
from pathlib import Path

import pytest

from kubeready.cli import main
from kubeready.loader import LoadError, parse_text

ROOT = Path(__file__).resolve().parent.parent
BAD, FIXED = str(ROOT / "examples" / "bad"), str(ROOT / "examples" / "fixed")


def test_parse_multi_document_with_line_numbers():
    text = (
        "# header\napiVersion: v1\nkind: Service\nmetadata: {name: a}\n"
        "---\n\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: b}\n"
    )
    objs = parse_text(text, "x.yaml")
    assert [(o.kind, o.name, o.line) for o in objs] == [("Service", "a", 2), ("Secret", "b", 8)]


def test_parse_skips_non_kubernetes_yaml_and_expands_lists():
    text = (
        "name: ci\non: push\n---\n"
        "apiVersion: v1\nkind: List\nitems:\n  - {apiVersion: v1, kind: ConfigMap, metadata: {name: c}}\n"
    )
    assert [o.kind for o in parse_text(text)] == ["ConfigMap"]


def test_parse_error_reports_location():
    with pytest.raises(LoadError, match="x.yaml:"):
        parse_text("apiVersion: v1\nkind: [unclosed\n", "x.yaml")


def test_exit_code_bad_examples_fail(capsys):
    assert main([BAD]) == 1
    assert "Workload scores" in capsys.readouterr().out


def test_exit_code_fixed_examples_pass(capsys):
    assert main([FIXED, "--fail-on", "info"]) == 0


def test_fail_on_none_never_fails(capsys):
    assert main([BAD, "--fail-on", "none"]) == 0


def test_fail_on_threshold(tmp_path, capsys):
    # Only a warning-level finding: passes at --fail-on error, fails at warning.
    f = tmp_path / "pdb.yaml"
    f.write_text(
        "apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata: {name: p}\n"
        "spec: {selector: {matchLabels: {app: x}}}\n"
    )
    assert main([str(f), "--fail-on", "error"]) == 0
    assert main([str(f), "--fail-on", "warning"]) == 1


def test_usage_errors_exit_2(tmp_path, capsys):
    assert main([str(tmp_path / "missing.yaml")]) == 2
    assert main([BAD, "--only", "not-a-check"]) == 2
    broken = tmp_path / "broken.yaml"
    broken.write_text("kind: [\n")
    assert main([str(broken)]) == 2


def test_sarif_to_file(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    assert main([BAD, "-f", "sarif", "-o", str(out), "--fail-on", "none"]) == 0
    data = json.loads(out.read_text())
    assert data["runs"][0]["results"]


def test_only_filter(capsys):
    main([BAD, "-f", "json", "--only", "image-tag"])
    data = json.loads(capsys.readouterr().out)
    assert {f["check"] for f in data["findings"]} == {"image-tag"}


def test_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    assert "service-selector" in capsys.readouterr().out


def test_only_hides_scores_in_table(capsys):
    main([BAD, "--only", "image-tag"])
    assert "Workload scores" not in capsys.readouterr().out
