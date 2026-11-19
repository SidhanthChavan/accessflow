# Fake Slack/GitHub/Google systems stored in a JSON file, so the demo runs
# without any API keys.
# TODO: real connectors (GitHub REST API, Slack SCIM, Google Admin SDK)
from __future__ import annotations

import json
from pathlib import Path

from ..models import Account, Employee
from .base import Connector


class SimulatedStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data: dict = json.loads(self.path.read_text()) if self.path.exists() else {}

    def system(self, name: str) -> dict:
        return self.data.setdefault(name, {"users": {}})["users"]

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")


class SimulatedConnector(Connector):
    def __init__(self, name: str, store: SimulatedStore):
        self.name = name
        self.store = store

    @property
    def _users(self) -> dict:
        return self.store.system(self.name)

    def _user(self, username: str) -> dict:
        if username not in self._users:
            raise KeyError(f"{self.name}: no such user '{username}'")
        return self._users[username]

    def list_accounts(self) -> dict[str, Account]:
        return {
            u: Account(u, set(d.get("groups", [])), d.get("enabled", True), d.get("managed", True))
            for u, d in self._users.items()
        }

    def create_account(self, employee: Employee) -> None:
        if employee.username in self._users:
            raise ValueError(f"{self.name}: user '{employee.username}' already exists")
        self._users[employee.username] = {
            "display_name": employee.full_name, "groups": [], "enabled": True, "managed": True,
        }

    def enable_account(self, username: str) -> None:
        self._user(username)["enabled"] = True

    def disable_account(self, username: str) -> None:
        self._user(username)["enabled"] = False

    def add_to_group(self, username: str, group: str) -> None:
        groups = self._user(username).setdefault("groups", [])
        if group not in groups:
            groups.append(group)
            groups.sort()

    def remove_from_group(self, username: str, group: str) -> None:
        groups = self._user(username).setdefault("groups", [])
        if group in groups:
            groups.remove(group)
