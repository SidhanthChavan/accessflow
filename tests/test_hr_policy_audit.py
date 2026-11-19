from __future__ import annotations

import json

import pytest

from accessflow.audit import AuditLog, verify
from accessflow.hr import HRFeedError, load_hr_feed
from accessflow.policy import PolicyError, load_policy

HEADER = ("employee_id,email,full_name,department,title,location,employment_type,"
          "manager_email,start_date,end_date\n")


def test_hr_feed_skips_bad_rows_without_crashing(tmp_path):
    f = tmp_path / "hr.csv"
    f.write_text(HEADER
                 + "1,a@x.io,A,Eng,Eng,London,employee,b@x.io,2024-01-01,\n"
                 + "2,not-an-email,B,Eng,Eng,London,employee,b@x.io,2024-01-01,\n"
                 + "3,a@x.io,C,Eng,Eng,London,employee,b@x.io,2024-01-01,\n"
                 + "4,d@x.io,D,Eng,Eng,London,contractor,b@x.io,2024-01-01,\n"
                 + "5,e@x.io,E,Eng,Eng,London,employee,b@x.io,2024-05-01,2024-01-01\n")
    employees, findings = load_hr_feed(f)
    assert [e.email for e in employees] == ["a@x.io", "d@x.io"]
    details = " ".join(x.detail for x in findings)
    assert "invalid email" in details and "duplicate email" in details
    assert "end_date before start_date" in details and "no end_date" in details


def test_hr_feed_missing_columns_is_fatal(tmp_path):
    f = tmp_path / "hr.csv"
    f.write_text("email,name\na@x.io,A\n")
    with pytest.raises(HRFeedError):
        load_hr_feed(f)


def test_policy_rejects_unknown_system(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("systems: [slack]\nbaseline: { jira: [x] }\n")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_policy_rejects_unknown_match_key(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("systems: [slack]\nrules:\n  - name: r\n    match: { salary: 1 }\n    grant: {}\n")
    with pytest.raises(PolicyError):
        load_policy(p)


def test_audit_log_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record(action="add_to_group", username=f"u{i}", status="success")
    assert verify(path)[0]

    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["username"] = "attacker"                      # rewrite history
    lines[1] = json.dumps(entry, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = verify(path)
    assert not ok and "line 2" in msg


def test_audit_log_detects_deleted_entry(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record(action="disable_account", username=f"u{i}", status="success")
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify(path)[0]


def test_audit_log_continues_chain_across_runs(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(username="a")
    AuditLog(path).record(username="b")                 # new process, same file
    assert verify(path) == (True, "audit log intact (2 entries)")
