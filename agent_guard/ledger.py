"""Append-only SHA-256 hash-chain ledger for policy decisions."""
from __future__ import annotations
import hashlib, json, os, threading
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64
_LOCK = threading.Lock()

def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

class HashChainLedger:
    def __init__(self, path: str | Path, max_bytes: int = 5 * 1024 * 1024):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        # Store decision metadata only; callers must not pass prompts, secrets, or raw tool output.
        safe = {k: event[k] for k in ("timestamp", "session_id", "call_id", "tool", "action", "reason", "rule_id") if k in event}
        with _LOCK:
            current_size = self.path.stat().st_size if self.path.exists() else 0
            if current_size >= self.max_bytes:
                raise RuntimeError("ledger capacity reached; refusing to overwrite evidence")
            previous = _GENESIS
            if self.path.exists() and current_size:
                with self.path.open("rb") as stream:
                    for line in stream:
                        row = json.loads(line)
                        previous = row["hash"]
            body = {"previous_hash": previous, "event": safe}
            digest = hashlib.sha256(_canonical(body)).hexdigest()
            row = {**body, "hash": digest}
            encoded = _canonical(row) + b"\n"
            if current_size + len(encoded) > self.max_bytes:
                raise RuntimeError("ledger capacity reached; refusing to overwrite evidence")
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, encoded)
                os.fsync(fd)
            finally:
                os.close(fd)
            return row

def verify_ledger(path: str | Path) -> dict[str, Any]:
    previous = _GENESIS
    count = 0
    with Path(path).open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            row = json.loads(line)
            if row.get("previous_hash") != previous:
                return {"valid": False, "records": count, "line": line_number, "reason": "previous_hash_mismatch"}
            body = {"previous_hash": row["previous_hash"], "event": row["event"]}
            expected = hashlib.sha256(_canonical(body)).hexdigest()
            if row.get("hash") != expected:
                return {"valid": False, "records": count, "line": line_number, "reason": "record_hash_mismatch"}
            previous = expected
            count += 1
    return {"valid": True, "records": count, "head": previous}
