# CLI entry point.
#   accessflow plan  --hr data/hr_feed.csv --policy config/policy.yaml
#   accessflow apply (same args)
#   accessflow verify-audit audit/audit.jsonl
from __future__ import annotations

import argparse
import getpass
import sys
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import AuditLog, verify
from .connectors import SimulatedConnector, SimulatedStore
from .engine import SafetyGuardError, apply_plan, build_plan
from .hr import load_hr_feed
from .policy import load_policy
from .report import write_access_review, write_html_report, write_plan_json

console = Console()
ACTION_STYLE = {
    "create_account": "green", "enable_account": "green", "add_to_group": "cyan",
    "remove_from_group": "yellow", "disable_account": "red",
}


def _build_connectors(policy, state_path: str, use_aws: bool):
    store = SimulatedStore(state_path)
    connectors = {s: SimulatedConnector(s, store) for s in policy.systems}
    if use_aws and "aws_iam" in policy.systems:
        from .connectors.aws_iam import AwsIamConnector
        connectors["aws_iam"] = AwsIamConnector()
    return store, connectors


def _print_plan(plan) -> None:
    s = plan.summary()
    console.rule(f"[bold]AccessFlow plan - {s['date']}")
    console.print(f"Joiners: [green]{s['joiners']}[/]  Movers/drift: [cyan]{s['movers']}[/]  "
                  f"Leavers: [red]{s['leavers']}[/]  Changes: [bold]{s['total_changes']}[/]")
    if plan.changes:
        t = Table(show_lines=False, header_style="bold")
        for col in ("System", "Action", "User", "Group", "Reason"):
            t.add_column(col)
        for c in plan.changes:
            t.add_row(c.system, f"[{ACTION_STYLE[c.action.value]}]{c.action.value}[/]",
                      c.username, c.group or "", c.reason)
        console.print(t)
    else:
        console.print("[green]Nothing to change.[/]")
    if plan.findings:
        t = Table(title="Findings", header_style="bold")
        for col in ("Severity", "Category", "Subject", "Detail"):
            t.add_column(col)
        colour = {"high": "red", "medium": "yellow", "low": "dim"}
        for f in plan.findings:
            t.add_row(f"[{colour.get(f.severity, '')}]{f.severity}[/]", f.category, f.subject, f.detail)
        console.print(t)
    for reason in plan.blocked_reasons:
        console.print(f"[bold red]SAFETY GUARD:[/] {reason}")


def _run(args, apply: bool) -> int:
    today = date.fromisoformat(args.today) if args.today else date.today()
    policy = load_policy(args.policy)
    employees, hr_findings = load_hr_feed(args.hr)
    store, connectors = _build_connectors(policy, args.state, args.aws)
    plan = build_plan(employees, policy, connectors, today, hr_findings)
    _print_plan(plan)

    out = Path(args.out)
    write_plan_json(plan, out / "plan.json")
    write_access_review(plan, out / "access_review.csv")
    write_html_report(plan, out / "report.html", mode="apply" if apply else "dry run (plan only)")
    console.print(f"\nReports written to [bold]{out}/[/] (report.html, plan.json, access_review.csv)")

    if not apply:
        if plan.changes:
            console.print("This was a dry run. Use `accessflow apply` to make the changes.")
        return 2 if plan.is_blocked else 0

    try:
        result = apply_plan(plan, connectors, AuditLog(args.audit), actor=args.actor, force=args.force)
    except SafetyGuardError as exc:
        console.print(f"[bold red]Not applying:[/] {exc}\n"
                      "Check the HR file. If the plan really is correct, re-run with --force.")
        return 3
    store.save()
    console.print(f"[bold green]Applied {result['applied']}[/] change(s), "
                  f"[bold red]{result['failed']} failed[/]. Audit log: {args.audit}")
    return 1 if result["failed"] else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="accessflow", description="Joiner-Mover-Leaver access automation")
    p.add_argument("--version", action="version", version=f"accessflow {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--hr", required=True, help="HR feed CSV export")
        sp.add_argument("--policy", required=True, help="access policy YAML")
        sp.add_argument("--state", default="data/systems_state.json",
                        help="state file for simulated systems")
        sp.add_argument("--aws", action="store_true", help="use real AWS IAM (boto3 credentials)")
        sp.add_argument("--today", help="override run date (YYYY-MM-DD), for testing/back-fills")
        sp.add_argument("--out", default="reports", help="report output directory")

    common(sub.add_parser("plan", help="show what would change (dry run, default)"))
    ap = sub.add_parser("apply", help="make the changes and write the audit log")
    common(ap)
    ap.add_argument("--audit", default="audit/audit.jsonl")
    ap.add_argument("--actor", default=getpass.getuser(), help="who is running this (for audit)")
    ap.add_argument("--force", action="store_true", help="override safety guard after human review")
    vp = sub.add_parser("verify-audit", help="check the audit log has not been tampered with")
    vp.add_argument("path")

    args = p.parse_args(argv)
    if args.cmd == "verify-audit":
        ok, msg = verify(args.path)
        console.print(("[green]OK[/] " if ok else "[bold red]TAMPERED[/] ") + msg)
        return 0 if ok else 1
    return _run(args, apply=args.cmd == "apply")


if __name__ == "__main__":
    sys.exit(main())
