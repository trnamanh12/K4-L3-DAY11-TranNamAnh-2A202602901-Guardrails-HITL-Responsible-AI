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
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and its start time until the matching output arrives."""
        key = request_id or user_id
        self._open[key] = {
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_clock": time.monotonic(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, decision layer and elapsed request time."""
        key = request_id or user_id
        opened = self._open.pop(key, None) or {
            "user_id": user_id,
            "input": None,
            "started_at": utc_now_iso(),
            "started_clock": time.monotonic(),
        }
        self.logs.append({
            "user_id": user_id,
            "input": opened["input"],
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "started_at": opened["started_at"],
            "timestamp": utc_now_iso(),
            "latency_ms": round((time.monotonic() - opened["started_clock"]) * 1000, 2),
            "request_id": request_id,
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
