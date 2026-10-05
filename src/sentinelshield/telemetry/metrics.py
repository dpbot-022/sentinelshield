import time
from collections import deque
from typing import Dict, Any, List
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    event_type: str  # "INJECTION_BLOCKED", "PII_SCRUBBED", "JSON_REPAIRED", "RATE_LIMIT_HIT", "PROXY_SUCCESS"
    severity: str    # "INFO", "WARNING", "HIGH", "CRITICAL"
    user_tier: str
    details: Dict[str, Any]


class GatewayMetrics:
    """Enterprise Gateway Observability & Audit Trail Engine"""

    def __init__(self, max_audit_events: int = 150):
        self.start_time = time.time()
        self.total_requests = 0
        self.successful_requests = 0
        self.blocked_injections = 0
        self.pii_redacted_count = 0
        self.self_healing_repairs = 0
        self.rate_limit_exceeded = 0
        self.total_latency_ms = 0.0
        self.audit_log: deque = deque(maxlen=max_audit_events)

    def record_event(self, event_type: str, severity: str, user_tier: str, details: Dict[str, Any]):
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_tier=user_tier,
            details=details,
        )
        self.audit_log.appendleft(event)

    def record_request_metrics(
        self,
        status: str,
        latency_ms: float,
        pii_count: int = 0,
        repaired: bool = False,
    ):
        self.total_requests += 1
        self.total_latency_ms += latency_ms
        if status == "SUCCESS" or status == "REPAIRED":
            self.successful_requests += 1
        if pii_count > 0:
            self.pii_redacted_count += pii_count
        if repaired:
            self.self_healing_repairs += 1

    def get_summary(self) -> Dict[str, Any]:
        uptime_seconds = round(time.time() - self.start_time, 1)
        avg_latency = (
            round(self.total_latency_ms / self.total_requests, 2)
            if self.total_requests > 0
            else 0.0
        )
        return {
            "uptime_seconds": uptime_seconds,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "blocked_injections": self.blocked_injections,
            "pii_entities_sanitized": self.pii_redacted_count,
            "self_healing_repairs_executed": self.self_healing_repairs,
            "rate_limit_blocks": self.rate_limit_exceeded,
            "average_latency_ms": avg_latency,
            "recent_audit_events_count": len(self.audit_log),
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [event.model_dump() for event in list(self.audit_log)[:limit]]

    def to_prometheus_format(self) -> str:
        lines = [
            "# HELP sentinelshield_requests_total Total gateway requests",
            "# TYPE sentinelshield_requests_total counter",
            f"sentinelshield_requests_total {self.total_requests}",
            "# HELP sentinelshield_blocked_injections_total Injections blocked by guardrails",
            "# TYPE sentinelshield_blocked_injections_total counter",
            f"sentinelshield_blocked_injections_total {self.blocked_injections}",
            "# HELP sentinelshield_pii_sanitized_total PII entities scrubbed in-memory",
            "# TYPE sentinelshield_pii_sanitized_total counter",
            f"sentinelshield_pii_sanitized_total {self.pii_redacted_count}",
            "# HELP sentinelshield_json_repairs_total Self-healing repairs completed",
            "# TYPE sentinelshield_json_repairs_total counter",
            f"sentinelshield_json_repairs_total {self.self_healing_repairs}",
            "# HELP sentinelshield_ratelimit_blocks_total Rate limit 429 rejections",
            "# TYPE sentinelshield_ratelimit_blocks_total counter",
            f"sentinelshield_ratelimit_blocks_total {self.rate_limit_exceeded}",
            "# HELP sentinelshield_uptime_seconds Service uptime in seconds",
            "# TYPE sentinelshield_uptime_seconds gauge",
            f"sentinelshield_uptime_seconds {round(time.time() - self.start_time, 1)}",
        ]
        return "\n".join(lines) + "\n"


metrics_collector = GatewayMetrics()
