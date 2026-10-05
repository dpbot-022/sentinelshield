import re
import json
import random
import asyncio
from typing import Optional
from sentinelshield.inference.base import BaseInferenceProvider


class SimulatorInferenceProvider(BaseInferenceProvider):
    """
    Mock inference engine for automated testing and offline verification.
    Generates dynamic schema-compliant JSON derived directly from the prompt.
    """

    def __init__(self, simulate_malformed: bool = False):
        self.simulate_malformed = simulate_malformed

    async def generate(
        self,
        prompt: str,
        system_prompt: str,
        json_mode: bool = True,
        temperature: float = 0.1,
        model: Optional[str] = None,
    ) -> str:
        await asyncio.sleep(0.01)

        is_reprompt = "CRITICAL ERROR" in prompt or "Fix the schema validation errors" in prompt

        # Detect schema
        schema_name = "CustomerSupportTicket"
        if "FinancialSentimentReport" in system_prompt or "FinancialSentimentReport" in prompt:
            schema_name = "FinancialSentimentReport"
        elif "SecurityVulnerabilityAudit" in system_prompt or "SecurityVulnerabilityAudit" in prompt:
            schema_name = "SecurityVulnerabilityAudit"
        elif "MedicalTriageSummary" in system_prompt or "MedicalTriageSummary" in prompt:
            schema_name = "MedicalTriageSummary"

        # Check for extracted PII tokens in prompt to reflect in response
        tokens_found = re.findall(r"<PII_[A-Z0-9_]+>", prompt)
        name_token = next((t for t in tokens_found if "NAME" in t), "Customer User")
        email_token = next((t for t in tokens_found if "EMAIL" in t), "user@corp.internal")

        # Extract words from prompt for realistic summary
        words = [w for w in re.findall(r"[A-Za-z0-9]+", prompt) if not w.startswith("PII") and len(w) > 2]
        extracted_summary = " ".join(words[:12]) if len(words) >= 4 else "User reported request requiring immediate triage."

        # If simulate_malformed requested and this is NOT a re-prompt, output broken JSON
        if self.simulate_malformed and not is_reprompt:
            if schema_name == "CustomerSupportTicket":
                return f"""Here is your JSON response:
```json
{{
    "ticket_id": "TCK-{random.randint(1000, 9999)}",
    "customer_name": "{name_token}",
    "customer_email": "{email_token}",
    "issue_category": "billing",
    "sentiment": "frustrated",
    "summary": "{extracted_summary}",
    "requires_human_escalation": "yes"
}}
```"""
            else:
                return '{"status": "broken", "details": "missing required fields"}'

        # Valid JSON response
        if schema_name == "CustomerSupportTicket":
            doc = {
                "ticket_id": f"TCK-{random.randint(1000, 9999)}",
                "customer_name": name_token,
                "customer_email": email_token,
                "issue_category": "billing",
                "priority": "high",
                "sentiment": "frustrated",
                "summary": extracted_summary,
                "action_items": [
                    "Verify user credentials and account identity",
                    "Review billing audit log for disputed transactions",
                    "Apply provisional account credit if dispute qualifies",
                ],
                "requires_human_escalation": True,
            }
        elif schema_name == "FinancialSentimentReport":
            doc = {
                "ticker": "NVDA",
                "company_name": "NVIDIA Corporation",
                "sentiment_score": 0.82,
                "confidence": 0.91,
                "recommendation": "BUY",
                "key_catalysts": ["Data center GPU sales acceleration", "Enterprise AI software margins"],
                "risk_factors": ["Supply chain advanced packaging constraints"],
                "target_price_horizon_months": 12,
            }
        elif schema_name == "SecurityVulnerabilityAudit":
            doc = {
                "cve_id": f"CVE-2026-{random.randint(1000, 9999)}",
                "component": "auth/token-bucket",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": extracted_summary,
                "remediation_steps": [
                    "Implement sliding window token bucket rate limiting",
                    "Enforce cryptographic JWT claim validation",
                ],
                "patch_available": True,
            }
        elif schema_name == "MedicalTriageSummary":
            doc = {
                "patient_identifier": name_token,
                "chief_complaint": extracted_summary,
                "triage_level": 2,
                "vital_indicators": {"bp": "138/88", "pulse": "92", "spo2": "96%"},
                "allergies_noted": ["Penicillin"],
                "immediate_intervention_required": True,
            }
        else:
            doc = {
                "ticket_id": f"TCK-{random.randint(1000, 9999)}",
                "customer_name": name_token,
                "customer_email": email_token,
                "issue_category": "general",
                "priority": "medium",
                "sentiment": "neutral",
                "summary": extracted_summary,
                "action_items": ["Review request and dispatch response"],
                "requires_human_escalation": False,
            }

        return json.dumps(doc)
