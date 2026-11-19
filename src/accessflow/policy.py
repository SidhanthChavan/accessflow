# Loads config/policy.yaml and works out which groups a person should be in
# based on their department, title, location and employment type.
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

from .models import Employee, Finding

MATCH_KEYS = {"department", "title_contains", "location", "employment_type"}


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    name: str
    match: dict
    grant: dict[str, list[str]] = field(default_factory=dict)
    deny: dict[str, list[str]] = field(default_factory=dict)

    def applies_to(self, emp: Employee) -> bool:
        for key, expected in self.match.items():
            options = expected if isinstance(expected, list) else [expected]
            options = [str(o).lower() for o in options]
            if key == "title_contains":
                if not any(o in emp.title.lower() for o in options):
                    return False
            else:
                if str(getattr(emp, key)).lower() not in options:
                    return False
        return True


@dataclass
class SoDRule:
    name: str
    conflicting: list[str]  # e.g. "aws_iam:prod-admin"


@dataclass
class AccessException:
    # temporary extra access with an expiry date
    username: str
    grant: dict[str, list[str]]
    expires: date
    approved_by: str
    ticket: str

    def active(self, today: date) -> bool:
        return today < self.expires


@dataclass
class Policy:
    systems: list[str]
    baseline: dict[str, list[str]]
    rules: list[Rule]
    sod_rules: list[SoDRule]
    protected_accounts: dict[str, list[str]]
    joiner_lead_days: int = 3
    orphan_action: str = "report"  # or "disable"
    max_disable_percent: float = 20.0
    max_changes: int = 500
    # without this, one leaver in a 1-person system = 100% and the guard trips
    guard_min_disables: int = 3
    exceptions: list[AccessException] = field(default_factory=list)

    def entitlements_for(self, emp: Employee, today: date | None = None) -> dict[str, set[str]]:
        # order matters: baseline, then grants, then denies (deny wins),
        # then any exceptions that haven't expired yet
        result: dict[str, set[str]] = {s: set() for s in self.systems}
        for system, groups in self.baseline.items():
            result[system].update(groups)
        matched = [r for r in self.rules if r.applies_to(emp)]
        for rule in matched:
            for system, groups in rule.grant.items():
                result[system].update(groups)
        for rule in matched:
            for system, groups in rule.deny.items():
                result[system].difference_update(groups)
        if today is not None:
            for exc in self.exceptions:
                if exc.username == emp.username and exc.active(today):
                    for system, groups in exc.grant.items():
                        result[system].update(groups)
        return result

    def is_protected(self, system: str, username: str) -> bool:
        return username in self.protected_accounts.get(system, [])

    def sod_findings(self, username: str, holdings: dict[str, set[str]]) -> list[Finding]:
        flat = {f"{s}:{g}" for s, groups in holdings.items() for g in groups}
        out = []
        for rule in self.sod_rules:
            hit = [c for c in rule.conflicting if c in flat]
            if len(hit) >= 2:
                out.append(Finding(
                    "high", "sod_violation", username,
                    f"{rule.name}: holds conflicting access {', '.join(sorted(hit))}",
                ))
        return out


def load_policy(path: str | Path) -> Policy:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    systems = raw.get("systems") or []
    if not systems:
        raise PolicyError("policy must declare at least one system")

    def _check_systems(block: dict, where: str) -> dict[str, list[str]]:
        block = block or {}
        unknown = set(block) - set(systems)
        if unknown:
            raise PolicyError(f"{where} references undeclared systems: {sorted(unknown)}")
        return {k: list(v or []) for k, v in block.items()}

    rules = []
    for i, r in enumerate(raw.get("rules") or []):
        name = r.get("name") or f"rule-{i}"
        match = r.get("match") or {}
        bad = set(match) - MATCH_KEYS
        if bad:
            raise PolicyError(f"rule '{name}' has unsupported match keys: {sorted(bad)}")
        rules.append(Rule(
            name=name,
            match=match,
            grant=_check_systems(r.get("grant"), f"rule '{name}' grant"),
            deny=_check_systems(r.get("deny"), f"rule '{name}' deny"),
        ))

    sod = [SoDRule(s["name"], list(s["conflicting"])) for s in raw.get("segregation_of_duties") or []]
    safety = raw.get("safety") or {}
    orphan_action = raw.get("orphan_action", "report")
    if orphan_action not in {"report", "disable"}:
        raise PolicyError("orphan_action must be 'report' or 'disable'")

    exceptions = []
    for e in raw.get("access_exceptions") or []:
        for req in ("username", "grant", "expires", "approved_by", "ticket"):
            if not e.get(req):
                raise PolicyError(f"access exception missing '{req}': {e}")
        expires = e["expires"]
        exceptions.append(AccessException(
            username=e["username"],
            grant=_check_systems(e["grant"], f"exception {e['ticket']}"),
            expires=expires if isinstance(expires, date) else date.fromisoformat(str(expires)),
            approved_by=e["approved_by"],
            ticket=e["ticket"],
        ))

    return Policy(
        exceptions=exceptions,
        systems=systems,
        baseline=_check_systems(raw.get("baseline"), "baseline"),
        rules=rules,
        sod_rules=sod,
        protected_accounts=_check_systems(raw.get("protected_accounts"), "protected_accounts"),
        joiner_lead_days=int(raw.get("joiner_lead_days", 3)),
        orphan_action=orphan_action,
        max_disable_percent=float(safety.get("max_disable_percent", 20)),
        max_changes=int(safety.get("max_changes", 500)),
        guard_min_disables=int(safety.get("min_disables_before_guard", 3)),
    )
