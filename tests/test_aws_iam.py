"""AWS IAM connector tested against moto's in-memory IAM (no real AWS needed)."""
from __future__ import annotations

from datetime import date

import boto3
import pytest
from moto import mock_aws

from accessflow.audit import AuditLog
from accessflow.connectors.aws_iam import AwsIamConnector
from accessflow.engine import apply_plan, build_plan
from accessflow.policy import load_policy

from .conftest import TODAY, emp

POLICY = """
systems: [aws_iam]
protected_accounts: { aws_iam: [terraform-ci] }
rules:
  - name: eng
    match: { department: Engineering }
    grant: { aws_iam: [developers] }
  - name: senior
    match: { department: Engineering, title_contains: Senior }
    grant: { aws_iam: [prod-readonly] }
"""


@pytest.fixture
def iam(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    with mock_aws():
        client = boto3.client("iam")
        for g in ("developers", "prod-readonly", "admins"):
            client.create_group(GroupName=g)
        yield client


@pytest.fixture
def aws_policy(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(POLICY)
    return load_policy(p)


def test_full_lifecycle_against_iam(iam, aws_policy, tmp_path):
    conn = AwsIamConnector(client=iam)
    connectors = {"aws_iam": conn}
    audit = AuditLog(tmp_path / "audit.jsonl")

    # Unmanaged users outside /accessflow/ must be invisible to the engine.
    iam.create_user(UserName="terraform-ci")
    iam.add_user_to_group(GroupName="admins", UserName="terraform-ci")

    # Joiner
    alice = emp("alice", title="Software Engineer")
    apply_plan(build_plan([alice], aws_policy, connectors, TODAY), connectors, audit)
    assert conn.list_accounts()["alice"].groups == {"developers"}
    user = iam.get_user(UserName="alice")["User"]
    assert user["Path"] == "/accessflow/"

    # Mover: promoted to Senior
    promoted = emp("alice", title="Senior Software Engineer")
    apply_plan(build_plan([promoted], aws_policy, connectors, TODAY), connectors, audit)
    assert conn.list_accounts()["alice"].groups == {"developers", "prod-readonly"}

    # Give her console + keys, then she leaves
    iam.create_login_profile(UserName="alice", Password="Sup3r-secret-pw!")
    key_id = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    leaver = emp("alice", title="Senior Software Engineer", end=date(2026, 11, 18))
    apply_plan(build_plan([leaver], aws_policy, connectors, TODAY), connectors, audit)

    acct = conn.list_accounts()["alice"]
    assert acct.groups == set() and acct.enabled is False
    keys = iam.list_access_keys(UserName="alice")["AccessKeyMetadata"]
    assert [(k["AccessKeyId"], k["Status"]) for k in keys] == [(key_id, "Inactive")]
    with pytest.raises(iam.exceptions.NoSuchEntityException):
        iam.get_login_profile(UserName="alice")

    # Idempotent, and the unmanaged CI user was never touched
    assert build_plan([leaver], aws_policy, connectors, TODAY).changes == []
    groups = iam.list_groups_for_user(UserName="terraform-ci")["Groups"]
    assert [g["GroupName"] for g in groups] == ["admins"]


def test_missing_group_is_recorded_as_failure_not_crash(iam, tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("systems: [aws_iam]\nbaseline: { aws_iam: [does-not-exist] }\n")
    policy = load_policy(p)
    connectors = {"aws_iam": AwsIamConnector(client=iam)}
    result = apply_plan(build_plan([emp("bob")], policy, connectors, TODAY),
                        connectors, AuditLog(tmp_path / "a.jsonl"))
    assert result == {"applied": 1, "failed": 1, "forced": False}
