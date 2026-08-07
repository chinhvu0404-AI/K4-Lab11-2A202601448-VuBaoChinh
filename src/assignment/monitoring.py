"""Monitoring counters, alerts, and deterministic snapshot replay."""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str

@dataclass
class MonitoringAlert:
    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0
    def check_metrics(self) -> list[Alert]:
        values = self.snapshot()
        checks = [("block_rate", values["block_rate"], self.block_rate_threshold),
                  ("rate_limit_hits", float(self.rate_limit_hits), float(self.rate_limit_hit_threshold)),
                  ("judge_fail_rate", values["judge_fail_rate"], self.judge_fail_rate_threshold)]
        existing = {a.metric for a in self.alerts}
        for metric, value, threshold in checks:
            if value >= threshold and metric not in existing:
                self.alerts.append(Alert(metric, value, threshold, f"{metric} threshold exceeded"))
        return self.alerts
    def export_json(self, filepath: str = "outputs/metrics.json"):
        self.check_metrics()
        target = Path(filepath); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8")
        return target
    def snapshot(self) -> dict:
        block_rate = self.blocked_requests / self.total_requests if self.total_requests else 0.0
        judge_fail_rate = self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        return {"total_requests": self.total_requests, "blocked_requests": self.blocked_requests,
                "block_rate": block_rate, "rate_limit_hits": self.rate_limit_hits,
                "judge_checks": self.judge_checks, "judge_fails": self.judge_fails,
                "judge_fail_rate": judge_fail_rate,
                "alerts": [{"metric": a.metric, "value": a.value, "threshold": a.threshold, "message": a.message} for a in self.alerts]}
    @classmethod
    def replay_snapshot(cls, snapshot: dict) -> dict:
        monitor = cls()
        for key in ("total_requests", "blocked_requests", "rate_limit_hits", "judge_checks", "judge_fails"):
            setattr(monitor, key, int(snapshot.get(key, 0)))
        monitor.check_metrics()
        return monitor.snapshot()

