import os
import pytest
from sentinelshield.config import settings
from sentinelshield.inference.groq_client import GroqInferenceProvider
from sentinelshield.guardrails.pii_sanitizer import pii_engine
from sentinelshield.schemas.registry import CustomerSupportTicket
from sentinelshield.repair.self_healing import self_healing_engine


@pytest.mark.asyncio
async def test_live_groq_inference():
    if not settings.GROQ_API_KEY:
        pytest.skip("GROQ_API_KEY not set")

    provider = GroqInferenceProvider(api_key=settings.GROQ_API_KEY, default_model=settings.GROQ_MODEL)

    raw_user_prompt = "Client Michael Chang (SSN: 444-55-6666, email: m.chang@enterprise.com) wants a refund on bill #9871."
    scrub_result = pii_engine.sanitize(raw_user_prompt, mode="tokenize")

    assert scrub_result.pii_found is True
    assert "444-55-6666" not in scrub_result.sanitized_text
    assert "<PII_SSN_1>" in scrub_result.sanitized_text

    system_prompt = (
        "You are SentinelShield's structured data intelligence core. "
        "Analyze the user input and produce output adhering strictly to the JSON schema for CustomerSupportTicket:\n"
        f"{CustomerSupportTicket.model_json_schema()}\n"
        "Output ONLY valid JSON. Keep all <PII_...> tokens intact in appropriate fields."
    )

    # Real call to Groq
    raw_response = await provider.generate(
        prompt=scrub_result.sanitized_text,
        system_prompt=system_prompt,
        json_mode=True,
        temperature=0.1,
        model=settings.GROQ_MODEL,
    )

    assert raw_response is not None
    assert len(raw_response) > 10

    # Real Pydantic validation and self-healing verification
    instance, report = await self_healing_engine.validate_and_heal(
        raw_output=raw_response,
        target_model=CustomerSupportTicket,
        inference_provider=provider,
        system_prompt=system_prompt,
        model_name=settings.GROQ_MODEL,
    )

    assert instance is not None
    assert isinstance(instance, CustomerSupportTicket)

    # Real rehydration of verified output
    rehydrated = pii_engine.rehydrate(instance.model_dump(), scrub_result.token_map)
    assert "Michael Chang" in str(rehydrated) or "m.chang@enterprise.com" in str(rehydrated)
    assert "<PII_" not in str(rehydrated)
