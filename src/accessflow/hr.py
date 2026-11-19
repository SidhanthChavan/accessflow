# Reads the HR export (CSV). This is the list of who actually works here.
from __future__ import annotations

import csv
import re
from datetime import date
from pathlib import Path

from .models import Employee, Finding

REQUIRED_COLUMNS = {
    "employee_id", "email", "full_name", "department", "title", "location",
    "employment_type", "manager_email", "start_date", "end_date",
}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class HRFeedError(ValueError):
    pass


def _parse_date(value: str) -> date | None:
    value = (value or "").strip()
    return date.fromisoformat(value) if value else None


def load_hr_feed(path: str | Path) -> tuple[list[Employee], list[Finding]]:
    # Bad rows get skipped and reported, so one typo in the HR file
    # doesn't stop the whole run.
    employees: list[Employee] = []
    findings: list[Finding] = []
    seen_ids: set[str] = set()
    seen_emails: set[str] = set()

    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise HRFeedError(f"HR feed missing columns: {sorted(missing)}")

        for line_no, row in enumerate(reader, start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            subject = row.get("email") or f"line {line_no}"
            try:
                if not EMAIL_RE.match(row["email"]):
                    raise ValueError(f"invalid email '{row['email']}'")
                if row["employee_id"] in seen_ids:
                    raise ValueError(f"duplicate employee_id {row['employee_id']}")
                if row["email"].lower() in seen_emails:
                    raise ValueError("duplicate email")
                if row["employment_type"] not in {"employee", "contractor"}:
                    raise ValueError(f"unknown employment_type '{row['employment_type']}'")
                start = _parse_date(row["start_date"])
                if start is None:
                    raise ValueError("missing start_date")
                end = _parse_date(row["end_date"])
                if end is not None and end < start:
                    raise ValueError("end_date before start_date")
                if row["employment_type"] == "contractor" and end is None:
                    findings.append(Finding(
                        "medium", "data_quality", row["email"],
                        "Contractor has no end_date; access will never expire automatically.",
                    ))
            except ValueError as exc:
                findings.append(Finding("high", "data_quality", subject, f"Row skipped: {exc}"))
                continue

            seen_ids.add(row["employee_id"])
            seen_emails.add(row["email"].lower())
            employees.append(Employee(
                employee_id=row["employee_id"],
                email=row["email"].lower(),
                full_name=row["full_name"],
                department=row["department"],
                title=row["title"],
                location=row["location"],
                employment_type=row["employment_type"],
                manager_email=row["manager_email"].lower(),
                start_date=start,
                end_date=end,
            ))
    return employees, findings
