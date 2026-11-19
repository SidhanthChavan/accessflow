# Data classes used everywhere else.
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import Enum


class Lifecycle(str, Enum):
    JOINER = "joiner"      # hasn't started yet
    ACTIVE = "active"
    LEAVER = "leaver"      # end date has passed


class Action(str, Enum):
    CREATE_ACCOUNT = "create_account"
    ENABLE_ACCOUNT = "enable_account"  # for re-hires
    ADD_TO_GROUP = "add_to_group"
    REMOVE_FROM_GROUP = "remove_from_group"
    DISABLE_ACCOUNT = "disable_account"


@dataclass(frozen=True)
class Employee:
    employee_id: str
    email: str
    full_name: str
    department: str
    title: str
    location: str
    employment_type: str  # employee or contractor
    manager_email: str
    start_date: date
    end_date: date | None = None

    def lifecycle(self, today: date) -> Lifecycle:
        if self.end_date is not None and self.end_date <= today:
            return Lifecycle.LEAVER
        if self.start_date > today:
            return Lifecycle.JOINER
        return Lifecycle.ACTIVE

    @property
    def username(self) -> str:
        return self.email.split("@", 1)[0].lower()


@dataclass
class Account:
    username: str
    groups: set[str] = field(default_factory=set)
    enabled: bool = True
    managed: bool = True  # False for bots/service accounts, we leave those alone


@dataclass(frozen=True)
class Change:
    system: str
    action: Action
    username: str
    group: str | None = None
    reason: str = ""

    def describe(self) -> str:
        target = f" {self.group}" if self.group else ""
        return f"[{self.system}] {self.action.value} {self.username}{target} ({self.reason})"

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "action": self.action.value,
            "username": self.username,
            "group": self.group,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Finding:
    # something a person should look at (we don't auto-fix these)
    severity: str  # high / medium / low
    category: str
    subject: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "subject": self.subject,
            "detail": self.detail,
        }
