# Writes the HTML report, the access review CSV and plan.json
from __future__ import annotations

import csv
import json
from pathlib import Path

from jinja2 import Environment, select_autoescape

from .engine import Plan

TEMPLATE_PATH = Path(__file__).parent / "templates" / "report.html"

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def write_html_report(plan: Plan, path: str | Path, mode: str = "dry run") -> Path:
    env = Environment(autoescape=select_autoescape(default=True))
    findings = sorted(plan.findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.subject))
    html = env.from_string(TEMPLATE_PATH.read_text()).render(
        s=plan.summary(), changes=plan.changes, findings=findings, mode=mode
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def write_access_review(plan: Plan, path: str | Path) -> Path:
    # one row per person per group, managers fill in the last column
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["manager_email", "employee_email", "full_name", "department", "title",
                    "system", "group", "decision (keep/revoke)"])
        for username in sorted(plan.desired):
            emp = plan.employees[username]
            for system, groups in sorted(plan.desired[username].items()):
                for g in sorted(groups):
                    w.writerow([emp.manager_email, emp.email, emp.full_name, emp.department,
                                emp.title, system, g, ""])
    return path


def write_plan_json(plan: Plan, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": plan.summary(),
        "changes": [c.to_dict() for c in plan.changes],
        "findings": [f.to_dict() for f in plan.findings],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
