import pytest
from sentinelshield.guardrails.pii_sanitizer import pii_engine, luhn_checksum_valid


def test_luhn_checksum():
    # Valid test visa card
    assert luhn_checksum_valid("4532015112830366") is True
    # Invalid card
    assert luhn_checksum_valid("4532015112830369") is False


def test_pii_sanitization_and_tokenization():
    raw_prompt = (
        "Client Alice Walker (SSN: 123-45-6789, email: alice.walker@enterprise.com, "
        "phone: 415-555-0199) requests record lookup."
    )
    res = pii_engine.sanitize(raw_prompt, mode="tokenize")

    assert res.pii_found is True
    assert "123-45-6789" not in res.sanitized_text
    assert "alice.walker@enterprise.com" not in res.sanitized_text
    assert "<PII_SSN_1>" in res.sanitized_text
    assert "<PII_EMAIL_1>" in res.sanitized_text
    assert "<PII_PHONE_1>" in res.sanitized_text

    # Verify token map contains raw entities strictly in memory
    assert res.token_map["<PII_SSN_1>"] == "123-45-6789"
    assert res.token_map["<PII_EMAIL_1>"] == "alice.walker@enterprise.com"


def test_pii_rehydration():
    token_map = {
        "<PII_NAME_1>": "Bob Vance",
        "<PII_SSN_1>": "987-65-4321",
        "<PII_EMAIL_1>": "bob@vancecooling.com",
    }
    model_output = {
        "customer_name": "<PII_NAME_1>",
        "customer_email": "<PII_EMAIL_1>",
        "notes": "Verified identity using SSN <PII_SSN_1> successfully.",
    }
    rehydrated = pii_engine.rehydrate(model_output, token_map)

    assert rehydrated["customer_name"] == "Bob Vance"
    assert rehydrated["customer_email"] == "bob@vancecooling.com"
    assert "987-65-4321" in rehydrated["notes"]
    assert "<PII_" not in str(rehydrated)


def test_pii_redaction_mode():
    raw_prompt = "Contact user at john.doe@cybersec.io regarding emergency alert."
    res = pii_engine.sanitize(raw_prompt, mode="redact")
    assert "[REDACTED_EMAIL]" in res.sanitized_text
    assert "john.doe@cybersec.io" not in res.sanitized_text
