from __future__ import annotations

import textwrap
from datetime import date
from pathlib import Path

import pytest

from accessflow.connectors import SimulatedConnector, SimulatedStore
from accessflow.models import Employee
from accessflow.policy import load_policy

TODAY = date(2026, 11, 19)
ROOT = Path(__file__).resolve().parents[1]

POLICY_YAML = textwrap.dedent("""
    systems: [slack, github]
    joiner_lead_days: 3
    orphan_action: disable
    safety: { max_disable_percent: 50, max_changes: 100 }
    protected_accounts: { github: [ci-bot] }
    baseline: { slack: [general] }
    rules:
      - name: eng
        match: { department: Engineering }
        grant: { github: [engineering], slack: [eng] }
      - name: finance-mgr
        match: { department: Finance, title_contains: Manager }
        grant: { github: [approvers] }
      - name: finance-ap
        match: { department: Finance, title_contains: Payable }
        grant: { github: [payments] }
      - name: contractors
        match: { employment_type: contractor }
        deny: { slack: [general] }
        grant: { slack: [contractors] }
    segregation_of_duties:
      - name: maker-checker
        conflicting: [github:approvers, github:payments]
    access_exceptions:
      - username: alice
        grant: { github: [prod-admin] }
        expires: 2026-12-01
        approved_by: cto@x.io
        ticket: T-1
      - username: bob
        grant: { github: [prod-admin] }
        expires: 2026-11-01
        approved_by: cto@x.io
        ticket: T-2
""")


def emp(name, dept="Engineering", title="Engineer", etype="employee",
        start=date(2024, 1, 1), end=None, location="London"):
    return Employee(
        employee_id=f"E-{name}", email=f"{name}@x.io", full_name=name.title(),
        department=dept, title=title, location=location, employment_type=etype,
        manager_email="boss@x.io", start_date=start, end_date=end,
    )


@pytest.fixture
def policy(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML)
    return load_policy(p)


@pytest.fixture
def store(tmp_path):
    return SimulatedStore(tmp_path / "state.json")


@pytest.fixture
def connectors(store, policy):
    return {s: SimulatedConnector(s, store) for s in policy.systems}
