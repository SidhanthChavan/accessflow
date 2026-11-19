# Resets data/systems_state.json to a messy "before" state for the demo.
# Run this before `accessflow apply` if you want to start over.
from __future__ import annotations

import dataclasses
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from accessflow.hr import load_hr_feed  # noqa: E402
from accessflow.policy import load_policy  # noqa: E402

SNAPSHOT_DATE = date(2026, 11, 1)
NOT_YET_PROVISIONED = {"ravi.sharma", "emma.wilson"}


def main(out: Path = ROOT / "data" / "systems_state.json") -> None:
    policy = load_policy(ROOT / "config" / "policy.yaml")
    employees, _ = load_hr_feed(ROOT / "data" / "hr_feed.csv")
    state = {s: {"users": {}} for s in policy.systems}

    def put(system, user, groups, enabled=True, managed=True):
        state[system]["users"][user] = {
            "display_name": user, "groups": sorted(groups), "enabled": enabled, "managed": managed,
        }

    for emp in employees:
        if emp.username in NOT_YET_PROVISIONED:
            continue
        if emp.username == "olivia.green":
            # left last year, coming back this month
            for s in policy.systems:
                put(s, emp.username, [], enabled=False)
            continue
        if emp.username == "tom.baker":
            # moved from Data to Engineering but still has his old access
            emp = dataclasses.replace(emp, department="Data", title="Data Analyst")
        for system, groups in policy.entitlements_for(emp, SNAPSHOT_DATE).items():
            if groups:
                put(system, emp.username, groups)

    # access someone added by hand and never removed
    state["google_workspace"]["users"]["daniel.reed"]["groups"].append("finance-approvers")
    state["github"]["users"]["lucy.chen"]["groups"].append("engineering")
    state["aws_iam"]["users"]["mia.wong"] = {
        "display_name": "mia.wong", "groups": ["developers"], "enabled": True, "managed": True}

    # accounts with no matching person in HR
    put("slack", "temp.vendor", ["general", "eng"])
    put("github", "old-intern", ["engineering"])
    put("aws_iam", "j.smith-legacy", ["developers", "prod-readonly"])

    # service accounts, should never be touched
    put("aws_iam", "terraform-ci", ["prod-admin"])
    put("aws_iam", "break-glass-admin", ["prod-admin"])
    put("slack", "deploy-bot", ["eng"], managed=False)

    for s in state.values():
        for u in s["users"].values():
            u["groups"] = sorted(set(u["groups"]))
    out.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(f"seeded demo state: {out}")


if __name__ == "__main__":
    main()
