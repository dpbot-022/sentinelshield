import time
import os
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import FastAPI, Depends, Request, HTTPException, status, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from sentinelshield.config import settings
from sentinelshield.auth.jwt_handler import (
    create_access_token,
    get_current_user,
    get_current_user_optional,
    require_tier,
)
from sentinelshield.auth.users import authenticate_user, USERS_DB
from sentinelshield.ratelimit.token_bucket import rate_limiter
from sentinelshield.guardrails.injection_scanner import scanner
from sentinelshield.guardrails.pii_sanitizer import pii_engine
from sentinelshield.schemas.registry import (
    get_schema_model,
    get_schema_definitions,
    SCHEMA_REGISTRY,
)
from sentinelshield.schemas.base_models import (
    TokenRequest,
    QuickTokenRequest,
    TokenResponse,
    GuardrailProxyRequest,
    GuardrailProxyResponse,
    LatencyBreakdown,
    SelfHealingReport,
)
from sentinelshield.inference.base import BaseInferenceProvider
from sentinelshield.inference.simulator import SimulatorInferenceProvider
from sentinelshield.inference.ollama_client import OllamaInferenceProvider
from sentinelshield.inference.groq_client import GroqInferenceProvider
from sentinelshield.repair.self_healing import self_healing_engine
from sentinelshield.telemetry.metrics import metrics_collector


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade AI Guardrail & Security Gateway microservice with zero-trust PII sanitization and sub-100ms self-healing JSON validation.",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for Dashboard UI
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the rich SentinelShield Security Gateway Dashboard"""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return HTMLResponse("<h1>SentinelShield Gateway API is running. Visit /docs for OpenAPI specs.</h1>")


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "providers_available": ["simulator", "ollama", "groq"],
        "active_schemas": list(SCHEMA_REGISTRY.keys()),
        "uptime_seconds": metrics_collector.get_summary()["uptime_seconds"],
    }


# ==========================================
# AUTH & RBAC ENDPOINTS
# ==========================================

@app.post("/api/v1/auth/token", response_model=TokenResponse)
async def login_for_access_token(request_data: TokenRequest):
    """Authenticate with username & password to receive an RBAC JWT token"""
    user = authenticate_user(request_data.username, request_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password. Check demo credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = {
        "sub": user["username"],
        "username": user["username"],
        "role": user["role"],
        "tier": user["tier"],
    }
    token = create_access_token(claims)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_info={
            "username": user["username"],
            "role": user["role"],
            "tier": user["tier"],
            "email": user["email"],
        },
    )


@app.post("/api/v1/auth/quick-token", response_model=TokenResponse)
async def quick_token(request_data: QuickTokenRequest):
    """Generate quick demo tokens for specific tiers (guest, tier-1, tier-2, admin)"""
    tier = request_data.tier if request_data.tier in settings.RATE_LIMIT_TIERS else "tier-1"
    claims = {
        "sub": request_data.username,
        "username": request_data.username,
        "role": request_data.role,
        "tier": tier,
    }
    token = create_access_token(claims)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_info={
            "username": request_data.username,
            "role": request_data.role,
            "tier": tier,
            "demo": True,
        },
    )


# ==========================================
# STANDALONE GUARDRAIL ENDPOINTS
# ==========================================

@app.post("/api/v1/guardrail/scan-injection")
async def scan_prompt_injection(payload: Dict[str, str]):
    """Analyze a raw text prompt for adversarial injection or jailbreak patterns"""
    prompt = payload.get("prompt", "")
    res = scanner.scan(prompt)
    return res


@app.post("/api/v1/guardrail/scrub-pii")
async def scrub_pii(payload: Dict[str, Any]):
    """Sanitize PII entities from text strictly in memory"""
    prompt = payload.get("text", "")
    mode = payload.get("mode", "tokenize")
    res = pii_engine.sanitize(prompt, mode=mode)
    return res


@app.get("/api/v1/schemas")
async def list_registered_schemas():
    """Retrieve all supported Pydantic v2 schemas and JSON Schemas"""
    return get_schema_definitions()


# ==========================================
# CORE ENTERPRISE PROXY GATEWAY
# ==========================================

def get_inference_provider(provider_type: str, simulate_malformed: bool = False) -> BaseInferenceProvider:
    if provider_type == "ollama":
        return OllamaInferenceProvider()
    elif provider_type == "groq":
        return GroqInferenceProvider()
    else:
        # Default or fallback to high-fidelity simulator
        return SimulatorInferenceProvider(simulate_malformed=simulate_malformed)


@app.post("/api/v1/proxy/generate", response_model=GuardrailProxyResponse)
async def proxy_generate(
    proxy_request: GuardrailProxyRequest,
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user_optional),
):
    """
    Main Gateway Endpoint:
    1. Authenticates & enforces sliding window token bucket rate limit per user tier
    2. Scans for adversarial prompt injections / jailbreaks
    3. Scrubs PII strictly in-memory into bidirectional ephemeral tokens
    4. Executes inference via target provider (Ollama / Groq / Simulator)
    5. Validates output with Pydantic v2 Rust core
    6. Intercepts failures with Sub-100ms Self-Healing JSON Repair Loop
    7. Rehydrates PII safely on response for authorized caller
    8. Records observability metrics
    """
    t_start = time.perf_counter()
    latencies = LatencyBreakdown()

    user_tier = current_user.get("tier", "guest")
    user_id = current_user.get("username", "guest")

    # Step 1 & 2: Rate Limiting Enforcement
    t_rate_start = time.perf_counter()
    try:
        await rate_limiter.check_rate_limit(request, user_tier=user_tier, user_id=user_id)
    except HTTPException as e:
        metrics_collector.rate_limit_exceeded += 1
        metrics_collector.record_event(
            event_type="RATE_LIMIT_HIT",
            severity="WARNING",
            user_tier=user_tier,
            details={"client_ip": request.client.host if request.client else "unknown", "tier": user_tier},
        )
        raise e
    latencies.rate_limit_ms = round((time.perf_counter() - t_rate_start) * 1000.0, 2)

    # Attach rate limit response headers
    if hasattr(request.state, "ratelimit_limit"):
        response.headers["X-RateLimit-Limit"] = request.state.ratelimit_limit
        response.headers["X-RateLimit-Remaining"] = request.state.ratelimit_remaining
        response.headers["X-RateLimit-Reset"] = request.state.ratelimit_reset

    # Step 3: Prompt Injection & Jailbreak Defense
    t_inject_start = time.perf_counter()
    scan_verdict = scanner.scan(proxy_request.prompt)
    latencies.injection_scan_ms = round((time.perf_counter() - t_inject_start) * 1000.0, 2)

    if not scan_verdict.is_safe:
        metrics_collector.blocked_injections += 1
        metrics_collector.record_event(
            event_type="INJECTION_BLOCKED",
            severity="CRITICAL",
            user_tier=user_tier,
            details={
                "threat_level": scan_verdict.threat_level,
                "detected_patterns": scan_verdict.detected_patterns,
                "prompt_sample": proxy_request.prompt[:80] + "...",
            },
        )
        latencies.total_pipeline_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        metrics_collector.record_request_metrics(status="BLOCKED", latency_ms=latencies.total_pipeline_ms)

        return GuardrailProxyResponse(
            status="BLOCKED",
            structured_data=None,
            security_verdict=f"BLOCKED: {scan_verdict.reason}",
            threat_details=scan_verdict,
            pii_summary={"sanitized": False, "entities_detected": {}},
            self_healing=SelfHealingReport(required=False, attempts=0, repaired=False, sub_100ms_achieved=True),
            latencies=latencies,
            model_used=proxy_request.model or proxy_request.provider,
        )

    # Step 4: Zero-Trust In-Memory PII Sanitization
    t_pii_start = time.perf_counter()
    scrub_result = pii_engine.sanitize(proxy_request.prompt, mode="tokenize")
    latencies.pii_scrub_ms = round((time.perf_counter() - t_pii_start) * 1000.0, 2)

    if scrub_result.pii_found:
        metrics_collector.record_event(
            event_type="PII_SCRUBBED",
            severity="INFO",
            user_tier=user_tier,
            details={
                "entities_detected": scrub_result.entities_detected,
                "token_count": len(scrub_result.token_map),
                "audit_hashes": scrub_result.audit_hashes,
            },
        )

    # Step 5: Resolve Target Pydantic v2 Schema
    try:
        target_model = get_schema_model(proxy_request.target_schema)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    system_instruction = (
        f"You are SentinelShield's structured data intelligence core. "
        f"Analyze the user input and produce output adhering strictly to the JSON schema for '{proxy_request.target_schema}'. "
        f"Output ONLY valid JSON. Keep any <PII_...> tokens intact in appropriate fields."
    )

    # Step 6: Upstream LLM Inference
    t_infer_start = time.perf_counter()
    provider = get_inference_provider(
        proxy_request.provider, simulate_malformed=proxy_request.simulate_malformed
    )

    try:
        raw_llm_response = await provider.generate(
            prompt=scrub_result.sanitized_text,
            system_prompt=system_instruction,
            json_mode=True,
            temperature=proxy_request.temperature,
            model=proxy_request.model,
        )
    except Exception as e:
        # Fallback to simulator if Ollama/Groq connection fails
        provider = SimulatorInferenceProvider(simulate_malformed=proxy_request.simulate_malformed)
        raw_llm_response = await provider.generate(
            prompt=scrub_result.sanitized_text,
            system_prompt=system_instruction,
            json_mode=True,
            temperature=proxy_request.temperature,
            model=proxy_request.model,
        )

    latencies.llm_inference_ms = round((time.perf_counter() - t_infer_start) * 1000.0, 2)

    # Step 7: Sub-100ms Self-Healing JSON Repair Loop
    t_heal_start = time.perf_counter()
    validated_instance, healing_report = await self_healing_engine.validate_and_heal(
        raw_output=raw_llm_response,
        target_model=target_model,
        inference_provider=provider,
        system_prompt=system_instruction,
        model_name=proxy_request.model,
    )
    healing_duration_ms = round((time.perf_counter() - t_heal_start) * 1000.0, 2)
    latencies.self_healing_ms = healing_duration_ms

    if healing_report.required:
        metrics_collector.record_event(
            event_type="JSON_REPAIRED",
            severity="WARNING",
            user_tier=user_tier,
            details={
                "attempts": healing_report.attempts,
                "initial_errors": healing_report.initial_errors,
                "repair_time_ms": healing_report.repair_time_ms,
                "schema": proxy_request.target_schema,
            },
        )

    # Step 8: Zero-Trust PII Rehydration or Redaction
    t_rehydrate_start = time.perf_counter()
    raw_data_dict = validated_instance.model_dump()

    if proxy_request.pii_mode == "rehydrate" and scrub_result.pii_found:
        final_data = pii_engine.rehydrate(raw_data_dict, scrub_result.token_map)
    elif proxy_request.pii_mode == "redact" and scrub_result.pii_found:
        redact_map = {token: f"[REDACTED_{token.split('_')[1]}]" for token in scrub_result.token_map}
        final_data = pii_engine.rehydrate(raw_data_dict, redact_map)
    else:
        final_data = raw_data_dict

    latencies.rehydration_ms = round((time.perf_counter() - t_rehydrate_start) * 1000.0, 2)
    latencies.total_pipeline_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

    overall_status = "REPAIRED" if healing_report.required else "SUCCESS"
    metrics_collector.record_request_metrics(
        status=overall_status,
        latency_ms=latencies.total_pipeline_ms,
        pii_count=len(scrub_result.token_map),
        repaired=healing_report.required,
    )

    return GuardrailProxyResponse(
        status=overall_status,
        structured_data=final_data,
        security_verdict="PASSED: Payload verified across all guardrail layers",
        threat_details=scan_verdict,
        pii_summary={
            "sanitized": scrub_result.pii_found,
            "entities_detected": scrub_result.entities_detected,
            "token_count": len(scrub_result.token_map),
            "mode_applied": proxy_request.pii_mode,
        },
        self_healing=healing_report,
        latencies=latencies,
        model_used=proxy_request.model or (
            "phi3:mini (local)" if proxy_request.provider == "ollama" else "sentinel-simulator-v2"
        ),
    )


# ==========================================
# OBSERVABILITY & AUDIT ENDPOINTS
# ==========================================

@app.get("/api/v1/telemetry/events")
async def get_security_audit_events(limit: int = 50):
    """Retrieve security audit events in reverse chronological order"""
    return metrics_collector.get_recent_events(limit=limit)


@app.get("/api/v1/telemetry/metrics")
async def get_metrics_summary():
    """Retrieve high-level gateway telemetry and KPIs"""
    return metrics_collector.get_summary()


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """Prometheus exposition format exporter"""
    return metrics_collector.to_prometheus_format()


def main():
    import uvicorn
    uvicorn.run("sentinelshield.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)


if __name__ == "__main__":
    main()
