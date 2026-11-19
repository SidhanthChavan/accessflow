"""End-to-end: the shipped demo data through the real CLI."""
from __future__ import annotations

import csv
import shutil

from accessflow.cli import main

from .conftest import ROOT


def test_demo_end_to_end(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("seed", ROOT / "scripts" / "seed_demo.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    state = tmp_path / "state.json"
    seed.main(out=state)

    hr = tmp_path / "hr.csv"
    shutil.copy(ROOT / "data" / "hr_feed.csv", hr)
    args = ["--hr", str(hr), "--policy", str(ROOT / "config" / "policy.yaml"),
            "--state", str(state), "--today", "2026-11-19", "--out", str(tmp_path / "r")]
    audit = tmp_path / "audit.jsonl"

    assert main(["plan", *args]) == 0
    assert (tmp_path / "r" / "report.html").exists()
    with open(tmp_path / "r" / "access_review.csv") as fh:
        rows = list(csv.DictReader(fh))
    assert {r["employee_email"] for r in rows} >= {"ravi.sharma@northwind.example"}
    assert not any(r["employee_email"].startswith("hannah.lee") and r["group"] for r in rows)

    assert main(["apply", *args, "--audit", str(audit), "--actor", "test"]) == 0
    assert main(["verify-audit", str(audit)]) == 0

    # Simulate a truncated HR export: header + 2 rows -> guard must block apply
    lines = hr.read_text().splitlines()
    hr.write_text("\n".join(lines[:3]) + "\n")
    assert main(["plan", *args]) == 2
    assert main(["apply", *args, "--audit", str(audit)]) == 3
