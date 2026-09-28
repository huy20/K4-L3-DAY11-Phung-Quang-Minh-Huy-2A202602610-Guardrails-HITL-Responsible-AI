"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the incoming message and start timestamp for latency."""
        rid = request_id or f"req-{len(self.logs) + 1}"
        self._open[rid] = time.monotonic()
        entry = {
            "request_id": rid,
            "user_id": user_id,
            "event": "input",
            "text": text,
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)
        return rid

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store the reply, the layer decision and the measured latency."""
        rid = request_id or f"req-{len(self.logs)}"
        started = self._open.pop(rid, None)
        latency_ms = (
            round((time.monotonic() - started) * 1000, 2)
            if started is not None
            else None
        )
        entry = {
            "request_id": rid,
            "user_id": user_id,
            "event": "output",
            "text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": latency_ms,
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
