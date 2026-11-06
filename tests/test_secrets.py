import pytest
from helpers import container, obj, run, workload


def env_workload(name, value):
    return workload(containers=[container(env=[{"name": name, "value": value}])])


@pytest.mark.parametrize(
    "name,value,reason",
    [
        ("DB_PASSWORD", "hunter2", "credential-like name"),
        ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", "AWS access key id"),
        ("DATABASE_URL", "postgres://app:s3cret@db:5432/app", "credentials in a URL"),
        ("JAVA_OPTS", "-Ddb.password=hunter2", "password assignment"),
        ("TLS_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIE", "private key"),
    ],
)
def test_plaintext_secret_in_env(name, value, reason):
    msgs = run(env_workload(name, value), check="plaintext-secret")
    assert len(msgs) == 1 and reason in msgs[0]


@pytest.mark.parametrize(
    "name,value",
    [
        ("LOG_LEVEL", "info"),
        ("DATABASE_URL", "postgres://db:5432/app"),
        ("PASSWORD_FILE_PATH", "/etc/app/pw"),
        ("DB_PASSWORD", "$(INJECTED_BY_SIDECAR)"),
    ],
)
def test_plaintext_secret_clean_values(name, value):
    assert run(env_workload(name, value), check="plaintext-secret") == []


def test_secret_key_ref_is_fine():
    c = container(env=[{"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}])
    assert run(workload(containers=[c]), check="plaintext-secret") == []


def test_plaintext_secret_in_configmap():
    cm = obj("ConfigMap", "cfg", data={"SMTP_PASSWORD": "mailpass", "LOG_LEVEL": "info"})
    assert run(cm, check="plaintext-secret") == [
        "data key 'SMTP_PASSWORD' contains a credential-like name with a literal value"
    ]


def test_secret_not_base64():
    s = obj("Secret", "keys", data={"good": "aGVsbG8=", "bad": "not base64!"})
    assert run(s, check="secret-encoding") == ["data key 'bad' is not valid base64"]


def test_secret_string_data_is_fine():
    s = obj("Secret", "keys", stringData={"token": "plain is allowed here"})
    assert run(s, check="secret-encoding") == []
