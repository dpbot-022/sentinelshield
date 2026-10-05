import re
import json
import asyncio
from typing import Optional, Dict, Any
from sentinelshield.inference.base import BaseInferenceProvider


class SimulatorInferenceProvider(BaseInferenceProvider):
    """
    High-Fidelity Open Model Inference Simulator.
    Simulates local open models (such as phi3:mini or qwen2.5:1.5b),
    including realistic formatting errors and dynamic recovery during
    the Self-Healing JSON re-prompt loop.
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
        # Simulate local inference latency (15-35ms)
        await asyncio.sleep(0.02)

        # Check if this is a Self-Healing Re-Prompt
        is_reprompt = "CRITICAL ERROR: Pydantic v2 validation failed" in prompt or "Fix the errors" in prompt

        # Detect target schema name from system prompt or prompt
        schema_name = "CustomerSupportTicket"
        if "FinancialSentimentReport" in system_prompt or "FinancialSentimentReport" in prompt:
            schema_name = "FinancialSentimentReport"
        elif "SecurityVulnerabilityAudit" in system_prompt or "SecurityVulnerabilityAudit" in prompt:
            schema_name = "SecurityVulnerabilityAudit"
        elif "MedicalTriageSummary" in system_prompt or "MedicalTriageSummary" in prompt:
            schema_name = "MedicalTriageSummary"

        # Check for extracted PII tokens in prompt to reflect in response
        tokens_found = re.findall(r"<PII_[A-Z0-9_]+>", prompt)
        name_token = next((t for t in tokens_found if "NAME" in t), "Valued Customer")
        email_token = next((t for t in tokens_found if "EMAIL" in t), "customer@corp.internal")

        # 1. If simulate_malformed is requested AND it's NOT a re-prompt, return broken JSON
        if self.simulate_malformed and not is_reprompt:
            return self._generate_broken_json(schema_name, name_token, email_token)

        # 2. Return valid schema-compliant JSON
        return self._generate_valid_json(schema_name, name_token, email_token, is_reprompt)

    def _generate_broken_json(self, schema_name: str, name_token: str, email_token: str) -> str:
        """
        Simulates common failure modes of small open models:
        - Markdown wrapper with extra conversational preamble
        - Type mismatch (e.g. sentiment_score as string instead of float)
        - Missing required fields (e.g. action_items missing or priority missing)
        - Trailing commas or syntax errors
        """
        if schema_name == "CustomerSupportTicket":
            return f"""Here is your requested JSON response:
```json
{{
    "ticket_id": "TCK-4819",
    "customer_name": "{name_token}",
    "customer_email": "{email_token}",
    "issue_category": "billing",
    "sentiment": "frustrated",
    "summary": "Customer experienced unexpected billing deduction and requests rapid reconciliation.",
    "requires_human_escalation": "yes"
}}
```
Hope this helps! Let me know if you need any adjustments."""
        elif schema_name == "FinancialSentimentReport":
            return f"""```json
{{
    "ticker": "NVDA",
    "company_name": "NVIDIA Corporation",
    "sentiment_score": "very bullish",
    "confidence": 0.94,
    "recommendation": "BUY",
    "key_catalysts": ["Datacenter demand acceleration"],
    "target_price_horizon_months": 12
}}
```"""
        else:
            return """```json
{
    "status": "partial",
    "details": "Missing required schema fields",
}
```"""

    def _generate_valid_json(self, schema_name: str, name_token: str, email_token: str, is_repaired: bool) -> str:
        """Generates strictly compliant JSON conforming to the Pydantic v2 schemas"""
        if schema_name == "CustomerSupportTicket":
            doc = {
                "ticket_id": "TCK-9021",
                "customer_name": name_token,
                "customer_email": email_token,
                "issue_category": "billing",
                "priority": "high",
                "sentiment": "frustrated",
                "summary": "Customer reported billing discrepancy and unauthenticated transaction on account.",
                "action_items": [
                    "Freeze questionable charge authorization",
                    "Verify user multi-factor authentication",
                    "Dispatch automated refund assessment to billing department",
                ],
                "requires_human_escalation": True,
            }
        elif schema_name == "FinancialSentimentReport":
            doc = {
                "ticker": "NVDA",
                "company_name": "NVIDIA Corporation",
                "sentiment_score": 0.85,
                "confidence": 0.92,
                "recommendation": "STRONG_BUY",
                "key_catalysts": [
                    "Hyperscaler AI accelerator capital expenditure expansion",
                    "Next-generation rack-scale architecture delivery",
                ],
                "risk_factors": [
                    "Supply-chain packaging capacity constraints",
                    "Geopolitical trade restrictions",
                ],
                "target_price_horizon_months": 12,
            }
        elif schema_name == "SecurityVulnerabilityAudit":
            doc = {
                "cve_id": "CVE-2026-4402",
                "component": "sentinelshield/gateway-proxy",
                "severity": "HIGH",
                "cvss_score": 7.8,
                "description": "Unsanitized user payload could lead to model context leakage without active guardrails.",
                "remediation_steps": [
                    "Enforce strict token-bucket per tier",
                    "Activate Zero-Trust in-memory PII sanitization",
                    "Enable Pydantic v2 self-healing re-prompting validation",
                ],
                "patch_available": True,
            }
        elif schema_name == "MedicalTriageSummary":
            doc = {
                "patient_identifier": name_token,
                "chief_complaint": "Acute respiratory distress and elevated heart rate following exertion.",
                "triage_level": 2,
                "vital_indicators": {
                    "blood_pressure": "142/90",
                    "heart_rate": "114 bpm",
                    "spo2": "93%",
                },
                "allergies_noted": ["Penicillin", "Sulfa drugs"],
                "immediate_intervention_required": True,
            }
        else:
            doc = {
                "ticket_id": "TCK-GENERIC-1",
                "customer_name": name_token,
                "customer_email": email_token,
                "issue_category": "general",
                "priority": "medium",
                "sentiment": "neutral",
                "summary": "Standard request successfully triaged and structured.",
                "action_items": ["Log transaction into security audit trail"],
                "requires_human_escalation": False,
            }

        return json.dumps(doc)
