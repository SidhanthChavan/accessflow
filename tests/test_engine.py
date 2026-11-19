from __future__ import annotations

from datetime import date

import pytest

from accessflow.audit import AuditLog
from accessflow.engine import SafetyGuardError, apply_plan, build_plan
from accessflow.models import Action

from .conftest import TODAY, emp


def actions(plan, user=None, system=None):
    return {(c.system, c.action, c.group) for c in plan.changes
            if (user is None or c.username == user) and (system is None or c.system == system)}


def test_joiner_gets_baseline_and_role_access(policy, connectors):
    plan = build_plan([emp("carol")], policy, connectors, TODAY)
    assert actions(plan, "carol") == {
        ("slack", Action.CREATE_ACCOUNT, None), ("slack", Action.ADD_TO_GROUP, "general"),
        ("slack", Action.ADD_TO_GROUP, "eng"),
        ("github", Action.CREATE_ACCOUNT, None), ("github", Action.ADD_TO_GROUP, "engineering"),
    }
    assert plan.joiners == {"carol"}


def test_joiner_not_provisioned_too_early(policy, connectors):
    future = emp("dave", start=date(2026, 12, 25))
    soon = emp("erin", start=date(2026, 11, 21))
    plan = build_plan([future, soon], policy, connectors, TODAY)
    users = {c.username for c in plan.changes}
    assert "dave" not in users and "erin" in users


def test_mover_loses_old_access_and_gains_new(policy, connectors, store):
    store.system("slack")["carol"] = {"groups": ["general", "eng"], "enabled": True}
    store.system("github")["carol"] = {"groups": ["engineering"], "enabled": True}
    moved = emp("carol", dept="Finance", title="Finance Manager")
    plan = build_plan([moved], policy, connectors, TODAY)
    assert actions(plan, "carol") == {
        ("slack", Action.REMOVE_FROM_GROUP, "eng"),
        ("github", Action.REMOVE_FROM_GROUP, "engineering"),
        ("github", Action.ADD_TO_GROUP, "approvers"),
    }
    assert plan.movers == {"carol"}


def test_leaver_removed_everywhere_and_disabled(policy, connectors, store):
    store.system("slack")["frank"] = {"groups": ["general", "eng"], "enabled": True}
    store.system("github")["frank"] = {"groups": ["engineering"], "enabled": True}
    plan = build_plan([emp("frank", end=date(2026, 11, 18))], policy, connectors, TODAY)
    disables = {c.system for c in plan.changes if c.action is Action.DISABLE_ACCOUNT}
    assert disables == {"slack", "github"}
    assert not any(c.action is Action.ADD_TO_GROUP for c in plan.changes)
    assert plan.leavers == {"frank"}


def test_leaver_on_last_day_keeps_access_until_end_date(policy, connectors, store):
    store.system("slack")["gina"] = {"groups": ["general", "eng"], "enabled": True}
    plan = build_plan([emp("gina", end=date(2026, 11, 20))], policy, connectors, TODAY)
    assert not any(c.action is Action.DISABLE_ACCOUNT for c in plan.changes)


def test_rehire_is_reenabled(policy, connectors, store):
    store.system("slack")["hal"] = {"groups": [], "enabled": False}
    plan = build_plan([emp("hal", dept="Sales")], policy, connectors, TODAY)
    assert ("slack", Action.ENABLE_ACCOUNT, None) in actions(plan, "hal")
    assert ("slack", Action.CREATE_ACCOUNT, None) not in actions(plan, "hal")


def test_contractor_deny_wins_over_baseline(policy):
    ent = policy.entitlements_for(emp("ivy", etype="contractor", end=date(2027, 1, 1)), TODAY)
    assert ent["slack"] == {"contractors", "eng"}


def test_orphans_disabled_but_protected_and_unmanaged_untouched(policy, connectors, store):
    store.system("github")["ghost"] = {"groups": ["engineering"], "enabled": True}
    store.system("github")["ci-bot"] = {"groups": ["engineering"], "enabled": True}
    store.system("slack")["svc"] = {"groups": ["eng"], "enabled": True, "managed": False}
    plan = build_plan([], policy, connectors, TODAY)
    touched = {(c.system, c.username) for c in plan.changes}
    assert touched == {("github", "ghost")}
    assert any(f.category == "orphan_account" for f in plan.findings)


def test_exceptions_grant_until_expiry(policy):
    alice = policy.entitlements_for(emp("alice"), TODAY)
    bob = policy.entitlements_for(emp("bob"), TODAY)
    assert "prod-admin" in alice["github"]
    assert "prod-admin" not in bob["github"]


def test_sod_violation_flagged(policy, connectors):
    policy.rules[1].match = {"department": "Finance"}   # misconfig: every finance user approves
    plan = build_plan([emp("jo", dept="Finance", title="Accounts Payable")], policy, connectors, TODAY)
    assert any(f.category == "sod_violation" and f.subject == "jo" for f in plan.findings)


def test_safety_guard_blocks_mass_disable(policy, connectors, store, tmp_path):
    for i in range(10):
        store.system("slack")[f"user{i}"] = {"groups": ["general"], "enabled": True}
    # Broken HR export: only 2 of 10 people present -> 8 orphans to disable
    plan = build_plan([emp("user0"), emp("user1")], policy, connectors, TODAY)
    assert plan.is_blocked
    with pytest.raises(SafetyGuardError):
        apply_plan(plan, connectors, AuditLog(tmp_path / "a.jsonl"))


def test_apply_is_idempotent_and_audited(policy, connectors, store, tmp_path):
    people = [emp("carol"), emp("dan", dept="Finance", title="Finance Manager")]
    audit = AuditLog(tmp_path / "audit.jsonl")
    first = build_plan(people, policy, connectors, TODAY)
    result = apply_plan(first, connectors, audit)
    assert result == {"applied": len(first.changes), "failed": 0, "forced": False}
    second = build_plan(people, policy, connectors, TODAY)
    assert second.changes == []


def test_one_failure_does_not_stop_the_run(policy, connectors, tmp_path):
    plan = build_plan([emp("carol"), emp("dan")], policy, connectors, TODAY)
    broken = connectors["github"]
    original = broken.add_to_group

    def flaky(username, group):
        if username == "carol":
            raise RuntimeError("GitHub API 502")
        original(username, group)

    broken.add_to_group = flaky
    result = apply_plan(plan, connectors, AuditLog(tmp_path / "audit.jsonl"))
    assert result["failed"] == 1 and result["applied"] == len(plan.changes) - 1
