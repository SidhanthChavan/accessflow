# Every system (AWS, Slack, GitHub...) gets its own connector class with
# these methods. The engine only calls these, never the APIs directly.
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Account, Employee


class Connector(ABC):
    name: str

    @abstractmethod
    def list_accounts(self) -> dict[str, Account]:
        ...

    @abstractmethod
    def create_account(self, employee: Employee) -> None: ...

    @abstractmethod
    def enable_account(self, username: str) -> None: ...

    @abstractmethod
    def disable_account(self, username: str) -> None:
        # disable, don't delete - we want to keep it for investigations
        ...

    @abstractmethod
    def add_to_group(self, username: str, group: str) -> None: ...

    @abstractmethod
    def remove_from_group(self, username: str, group: str) -> None: ...
