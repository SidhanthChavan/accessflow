# Audit log - one JSON line per change.
#
# Each line stores the hash of the line before it (same idea as a blockchain,
# just much simpler). If someone edits or deletes an old line, the hashes stop
# matching and verify() catches it.
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def record(self, **fields) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **fields,
            "prev_hash": self._last_hash,
        }
        entry["hash"] = _digest(entry)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._last_hash = entry["hash"]
        return entry


def verify(path: str | Path) -> tuple[bool, str]:
    prev = GENESIS
    count = 0
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False, f"chain broken at line {line_no}: previous entry missing or altered"
            if _digest(entry) != entry.get("hash"):
                return False, f"entry at line {line_no} was modified"
            prev = entry["hash"]
            count += 1
    return True, f"audit log intact ({count} entries)"
