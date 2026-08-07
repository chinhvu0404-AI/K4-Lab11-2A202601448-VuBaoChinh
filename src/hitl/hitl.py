"""Human-in-the-loop routing and review lifecycle for VinBank."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid

HIGH_RISK_ACTIONS = ["transfer_money", "close_account", "change_password", "delete_data", "update_personal_info"]

@dataclass
class RoutingDecision:
    action: str
    confidence: float
    reason: str
    priority: str
    requires_human: bool

@dataclass
class ReviewRequest:
    correlation_id: str
    intent: str
    proposed_action: str
    diff: str
    context: str
    status: str = "pending"
    reviewer_id: str | None = None
    decision: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ConfidenceRouter:
    HIGH_THRESHOLD, MEDIUM_THRESHOLD = 0.9, 0.7
    def route(self, response: str, confidence: float, action_type: str = "general") -> RoutingDecision:
        confidence = max(0.0, min(1.0, confidence))
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision("escalate", confidence, f"High-risk action: {action_type}", "high", True)
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision("auto_send", confidence, "High confidence", "low", False)
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision("queue_review", confidence, "Medium confidence — needs review", "normal", True)
        return RoutingDecision("escalate", confidence, "Low confidence — escalating", "high", True)

class HITLReviewQueue:
    """Fail-closed reviewer lifecycle for high-impact banking actions."""
    def __init__(self):
        self.requests: dict[str, ReviewRequest] = {}
    def create(self, *, intent: str, proposed_action: str, diff: str, context: str, correlation_id: str | None = None):
        request = ReviewRequest(correlation_id or str(uuid.uuid4()), intent, proposed_action, diff, context)
        self.requests[request.correlation_id] = request
        return request
    def decide(self, correlation_id: str, reviewer_id: str, approve: bool):
        request = self.requests[correlation_id]
        if request.status != "pending":
            raise ValueError("review request is no longer pending")
        request.reviewer_id = reviewer_id
        request.decision = "approved" if approve else "rejected"
        request.status = request.decision
        return request
    def timeout(self, correlation_id: str):
        request = self.requests[correlation_id]
        if request.status == "pending":
            request.status, request.decision = "timed_out", "timeout"
        return request

hitl_decision_points = [
    {"id": 1, "name": "Money transfer approval", "trigger": "Any transfer_money action regardless of confidence",
     "hitl_model": "human-in-the-loop", "context_needed": "Correlation ID, authenticated customer, beneficiary, amount, limits, and before/after balance diff",
     "example": "Transfer VND 50,000,000 to a newly added beneficiary",
     "approval_path": "Reviewer approves with identity; reject or timeout blocks the transfer",
     "audit_fields": "correlation_id, intent, proposed_action, diff, reviewer_id, decision, timestamp"},
    {"id": 2, "name": "Account closure or credential change", "trigger": "close_account or change_password request",
     "hitl_model": "human-in-the-loop", "context_needed": "Customer verification state, linked products, requested change and policy warnings",
     "example": "Customer requests account closure while a loan remains active",
     "approval_path": "Operations reviewer approves after verification; timeout fails closed",
     "audit_fields": "correlation_id, intent, verification evidence, diff, reviewer decision, timeout"},
    {"id": 3, "name": "Ambiguous or low-confidence advice", "trigger": "confidence below 0.9 for a material financial response",
     "hitl_model": "human-as-tiebreaker", "context_needed": "Original question, retrieved source provenance, draft answer, confidence and judge result",
     "example": "Conflicting documents give different loan eligibility guidance",
     "approval_path": "Reviewer edits/approves; reject sends a safe escalation response; timeout queues no action",
     "audit_fields": "correlation_id, sources, draft, confidence, judge verdict, reviewer decision"},
]

def test_confidence_router():
    router = ConfidenceRouter()
    for args in [("Balance", .95, "general"), ("Transfer", .99, "transfer_money")]:
        print(router.route(*args))

def test_hitl_points():
    for point in hitl_decision_points:
        print(point["name"], "—", point["trigger"])

