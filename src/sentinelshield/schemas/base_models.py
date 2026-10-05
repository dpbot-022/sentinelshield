from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from sentinelshield.guardrails.injection_scanner import InjectionScanResult


class TokenRequest(BaseModel):
    username: str
    password: str


class QuickTokenRequest(BaseModel):
    username: str = "developer"
    role: str = "developer"
    tier: str = "tier-2"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user_info: Dict[str, Any]


class GuardrailProxyRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="Raw user prompt potentially containing PII or adversarial injections",
        json_schema_extra={"example": "Customer John Doe (SSN: 000-12-3456, email: john.doe@example.com) reports double charge of $499 on his credit card. Please investigate."},
    )
    target_schema: str = Field(
        default="CustomerSupportTicket",
        description="Target Pydantic v2 schema for structured response compliance",
    )
    provider: str = Field(
        default="simulator",
        description="Inference provider: 'simulator', 'ollama', or 'groq'",
    )
    model: Optional[str] = Field(
        default=None,
        description="Specific model name (e.g. phi3:mini, qwen2.5:1.5b, llama3.2:3b, llama-3.1-8b-instant)",
    )
    pii_mode: str = Field(
        default="rehydrate",
        description="PII processing mode: 'rehydrate' (de-anonymized output), 'tokenize' (<PII_...> tokens), or 'redact' ([REDACTED] tokens)",
    )
    simulate_malformed: bool = Field(
        default=False,
        description="Force inference engine to produce malformed JSON to test the Self-Healing Re-Prompting Loop",
    )
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)


class LatencyBreakdown(BaseModel):
    auth_check_ms: float = 0.0
    rate_limit_ms: float = 0.0
    injection_scan_ms: float = 0.0
    pii_scrub_ms: float = 0.0
    llm_inference_ms: float = 0.0
    validation_ms: float = 0.0
    self_healing_ms: float = 0.0
    rehydration_ms: float = 0.0
    total_pipeline_ms: float = 0.0


class SelfHealingReport(BaseModel):
    required: bool = False
    attempts: int = 0
    repaired: bool = True
    sub_100ms_achieved: bool = True
    initial_errors: List[str] = Field(default_factory=list)
    re_prompt_sent: Optional[str] = None
    repair_time_ms: float = 0.0


class GuardrailProxyResponse(BaseModel):
    status: str = Field(description="'SUCCESS', 'BLOCKED', or 'REPAIRED'")
    structured_data: Optional[Dict[str, Any]] = None
    security_verdict: str
    threat_details: Optional[InjectionScanResult] = None
    pii_summary: Dict[str, Any]
    self_healing: SelfHealingReport
    latencies: LatencyBreakdown
    model_used: str
