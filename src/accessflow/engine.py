# Main logic. Works out what access people *should* have (HR + policy),
# compares it with what they actually have in each system, and builds a list
# of changes. apply_plan() then makes those changes.
#
# If you run it twice, the second run should find nothing to do.
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, timedelta

from .audit import AuditLog
from .connectors.base import Connector
from .models import Action, Change, Employee, Finding, Lifecycle
from .policy import Policy

ACTION_ORDER = {
    Action.CREATE_ACCOUNT: 0,
    Action.ENABLE_ACCOUNT: 1,
    Action.ADD_TO_GROUP: 2,
    Action.REMOVE_FROM_GROUP: 3,
    Action.DISABLE_ACCOUNT: 4,
}


class SafetyGuardError(RuntimeError):
    pass


@dataclass
class Plan:
    today: date
    changes: list[Change] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    joiners: set[str] = field(default_factory=set)
    movers: set[str] = field(default_factory=set)
    leavers: set[str] = field(default_factory=set)
    blocked_reasons: list[str] = field(default_factory=list)
    desired: dict[str, dict[str, set[str]]] = field(default_factory=dict)
    employees: dict[str, Employee] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return bool(self.blocked_reasons)

    def summary(self) -> dict:
        by_action = Counter(c.action.value for c in self.changes)
        by_sev = Counter(f.severity for f in self.findings)
        return {
            "date": self.today.isoformat(),
            "total_changes": len(self.changes),
            "joiners": len(self.joiners),
            "movers": len(self.movers),
            "leavers": len(self.leavers),
            "by_action": dict(by_action),
            "findings": dict(by_sev),
            "blocked": self.blocked_reasons,
        }


def build_plan(
    employees: list[Employee],
    policy: Policy,
    connectors: dict[str, Connector],
    today: date,
    hr_findings: list[Finding] | None = None,
) -> Plan:
    plan = Plan(today=today, findings=list(hr_findings or []))
    by_username: dict[str, Employee] = {}
    for emp in employees:
        if emp.username in by_username:
            plan.findings.append(Finding(
                "high", "data_quality", emp.email,
                f"Username '{emp.username}' collides with {by_username[emp.username].email}; skipped.",
            ))
            continue
        by_username[emp.username] = emp
    plan.employees = by_username

    # step 1: what should everyone have?
    lead = timedelta(days=policy.joiner_lead_days)
    for username, emp in by_username.items():
        stage = emp.lifecycle(today)
        if stage is Lifecycle.LEAVER:
            plan.desired[username] = {s: set() for s in policy.systems}
        elif stage is Lifecycle.JOINER and emp.start_date - today > lead:
            continue  # starts later, don't create accounts yet
        else:
            plan.desired[username] = policy.entitlements_for(emp, today)

    # step 2: compare with what's actually there, one system at a time
    for system in policy.systems:
        conn = connectors.get(system)
        if conn is None:
            plan.findings.append(Finding("medium", "config", system, "No connector configured; skipped."))
            continue
        actual = conn.list_accounts()

        for username, wanted_all in plan.desired.items():
            emp = by_username[username]
            wanted = wanted_all.get(system, set())
            is_leaver = emp.lifecycle(today) is Lifecycle.LEAVER
            acct = actual.get(username)

            if policy.is_protected(system, username) or (acct and not acct.managed):
                continue

            if is_leaver:
                if acct is None:
                    continue
                for g in sorted(acct.groups):
                    plan.changes.append(Change(system, Action.REMOVE_FROM_GROUP, username, g, "leaver"))
                if acct.enabled:
                    plan.changes.append(Change(system, Action.DISABLE_ACCOUNT, username, None,
                                               f"leaver (end date {emp.end_date})"))
                if acct.groups or acct.enabled:
                    plan.leavers.add(username)
                continue

            if not wanted and acct is None:
                continue  # doesn't need an account in this system
            if acct is None:
                plan.changes.append(Change(system, Action.CREATE_ACCOUNT, username, None, "joiner"))
                plan.joiners.add(username)
                current: set[str] = set()
            else:
                current = acct.groups
                if not acct.enabled:
                    plan.changes.append(Change(system, Action.ENABLE_ACCOUNT, username, None, "re-hire"))
                    plan.joiners.add(username)

            if acct is None:
                reason_add = "joiner"
            elif not acct.enabled:
                reason_add = "re-hire"
            else:
                reason_add = "role change"
            for g in sorted(wanted - current):
                plan.changes.append(Change(system, Action.ADD_TO_GROUP, username, g, reason_add))
            for g in sorted(current - wanted):
                plan.changes.append(Change(system, Action.REMOVE_FROM_GROUP, username, g,
                                           "no longer entitled"))
            if acct is not None and acct.enabled and (wanted ^ current):
                plan.movers.add(username)

        # accounts that don't belong to anyone in the HR file
        for username, acct in actual.items():
            if username in by_username or not acct.managed or policy.is_protected(system, username):
                continue
            if not acct.enabled and not acct.groups:
                continue
            plan.findings.append(Finding(
                "high", "orphan_account", f"{system}:{username}",
                "No matching person in HR"
                + (", disabled." if policy.orphan_action == "disable" else ", needs review."),
            ))
            if policy.orphan_action == "disable" and acct.enabled:
                plan.changes.append(Change(system, Action.DISABLE_ACCOUNT, username, None, "orphan account"))

        # if we're about to disable a big chunk of accounts, something is probably
        # wrong with the HR file (e.g. export cut off halfway), so block it
        enabled = sum(1 for a in actual.values() if a.enabled and a.managed)
        disables = sum(1 for c in plan.changes if c.system == system and c.action is Action.DISABLE_ACCOUNT)
        if (disables >= policy.guard_min_disables
                and disables / enabled * 100 > policy.max_disable_percent):
            plan.blocked_reasons.append(
                f"{system}: plan disables {disables}/{enabled} accounts "
                f"({disables / enabled:.0%}) - over the {policy.max_disable_percent:.0f}% safety limit"
            )

    if len(plan.changes) > policy.max_changes:
        plan.blocked_reasons.append(
            f"plan has {len(plan.changes)} changes - over the {policy.max_changes} safety limit"
        )

    # step 3: extra checks that get reported, not fixed automatically
    for username, holdings in plan.desired.items():
        plan.findings.extend(policy.sod_findings(username, holdings))
    for exc in policy.exceptions:
        if exc.username not in by_username:
            plan.findings.append(Finding("medium", "exception", exc.username,
                                         f"Exception {exc.ticket} references unknown user."))
        elif not exc.active(today):
            plan.findings.append(Finding("low", "exception", exc.username,
                                         f"Exception {exc.ticket} expired {exc.expires}; access revoked."))
        elif exc.expires - today <= timedelta(days=7):
            plan.findings.append(Finding("low", "exception", exc.username,
                                         f"Exception {exc.ticket} expires {exc.expires}."))

    plan.changes.sort(key=lambda c: (c.system, c.username, ACTION_ORDER[c.action], c.group or ""))
    return plan


def apply_plan(
    plan: Plan,
    connectors: dict[str, Connector],
    audit: AuditLog,
    actor: str = "accessflow",
    force: bool = False,
) -> dict:
    # if one change fails we log it and carry on with the rest
    if plan.is_blocked and not force:
        raise SafetyGuardError("; ".join(plan.blocked_reasons))

    ok = failed = 0
    for change in plan.changes:
        conn = connectors[change.system]
        try:
            if change.action is Action.CREATE_ACCOUNT:
                conn.create_account(plan.employees[change.username])
            elif change.action is Action.ENABLE_ACCOUNT:
                conn.enable_account(change.username)
            elif change.action is Action.ADD_TO_GROUP:
                conn.add_to_group(change.username, change.group)
            elif change.action is Action.REMOVE_FROM_GROUP:
                conn.remove_from_group(change.username, change.group)
            elif change.action is Action.DISABLE_ACCOUNT:
                conn.disable_account(change.username)
            audit.record(actor=actor, status="success", **change.to_dict())
            ok += 1
        except Exception as exc:
            audit.record(actor=actor, status="failed", error=str(exc), **change.to_dict())
            failed += 1
    return {"applied": ok, "failed": failed, "forced": force and plan.is_blocked}
