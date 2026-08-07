"""Correlation-aware, sanitized audit logging."""
from __future__ import annotations
import json
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone

class AuditLogPlugin:
    def __init__(self):
        self.name, self.logs, self._open = "audit_log", [], {}
    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        request_id = request_id or str(uuid.uuid4())
        self._open[request_id] = time.perf_counter()
        self.logs.append({"event": "input", "request_id": request_id, "user_id": user_id,
                          "timestamp": utc_now_iso(), "text": text})
        return request_id
    def record_output(self, *, user_id: str, text: str, blocked: bool = False,
                      layer: str | None = None, request_id: str | None = None, **extra):
        request_id = request_id or str(uuid.uuid4())
        started = self._open.pop(request_id, None)
        record = {"event": "output", "request_id": request_id, "user_id": user_id,
                  "timestamp": utc_now_iso(), "text": text, "blocked": blocked,
                  "layer": layer, "latency_ms": round((time.perf_counter()-started)*1000, 2) if started else None}
        record.update(extra)
        self.logs.append(record)
        return record
    def record_event(self, event: str, *, correlation_id: str | None = None, **fields):
        """Record an action/HITL policy decision using the same correlation key."""
        record = {"event": event, "request_id": correlation_id or str(uuid.uuid4()),
                  "timestamp": utc_now_iso()}
        record.update(fields)
        self.logs.append(record)
        return record

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        target = Path(filepath); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return target
    def replay_snapshot(self):
        return {"events": len(self.logs), "request_ids": sorted({r["request_id"] for r in self.logs})}

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


