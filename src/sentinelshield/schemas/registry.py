from typing import List, Dict, Any, Literal, Type
from pydantic import BaseModel, Field


class CustomerSupportTicket(BaseModel):
    """Structured Customer Support Ticket representation"""
    ticket_id: str = Field(description="Unique ticket identifier e.g. TCK-9821")
    customer_name: str = Field(description="Customer full name")
    customer_email: str = Field(description="Customer email address")
    issue_category: Literal["billing", "technical", "account", "security", "general"] = Field(
        description="Categorized domain of the customer request"
    )
    priority: Literal["low", "medium", "high", "urgent"] = Field(
        description="Triaged priority level"
    )
    sentiment: Literal["positive", "neutral", "negative", "frustrated"] = Field(
        description="Assessed customer emotional sentiment"
    )
    summary: str = Field(min_length=5, description="Concise synopsis of the issue")
    action_items: List[str] = Field(description="List of concrete operational remediation steps")
    requires_human_escalation: bool = Field(description="Whether a human supervisor must intervene")


class FinancialSentimentReport(BaseModel):
    """Quantitative & Qualitative Financial Market Analysis"""
    ticker: str = Field(description="Stock ticker symbol e.g. AAPL, NVDA, TSLA")
    company_name: str = Field(description="Legal entity name")
    sentiment_score: float = Field(ge=-1.0, le=1.0, description="Sentiment index from -1.0 (bearish) to +1.0 (bullish)")
    confidence: float = Field(ge=0.0, le=1.0, description="Analytical confidence interval 0 to 1")
    recommendation: Literal["STRONG_BUY", "BUY", "HOLD", "SELL", "STRONG_SELL"] = Field(
        description="Investment committee stance"
    )
    key_catalysts: List[str] = Field(description="Positive momentum drivers")
    risk_factors: List[str] = Field(description="Material macroeconomic and microeconomic risks")
    target_price_horizon_months: int = Field(ge=1, le=60, description="Forecast target duration in months")


class SecurityVulnerabilityAudit(BaseModel):
    """AppSec Vulnerability Intelligence Report"""
    cve_id: str = Field(description="CVE identifier e.g. CVE-2026-1184 or INTERNAL-SEC-01")
    component: str = Field(description="Affected library, service, or repository module")
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(description="NIST severity classification")
    cvss_score: float = Field(ge=0.0, le=10.0, description="CVSS 3.1 base score")
    description: str = Field(min_length=10, description="Technical flaw description")
    remediation_steps: List[str] = Field(description="Actionable mitigation instructions")
    patch_available: bool = Field(description="Whether a production patch is published")


class MedicalTriageSummary(BaseModel):
    """Clinical Emergency Triage Summary"""
    patient_identifier: str = Field(description="Patient identifier or token")
    chief_complaint: str = Field(description="Primary reported medical condition")
    triage_level: int = Field(ge=1, le=5, description="Emergency Severity Index (ESI) 1=resuscitation, 5=non-urgent")
    vital_indicators: Dict[str, str] = Field(description="Observed vitals e.g. bp, hr, spo2")
    allergies_noted: List[str] = Field(description="Recorded patient allergies or contraindications")
    immediate_intervention_required: bool = Field(description="True if life-threatening condition observed")


# Central Schema Registry
SCHEMA_REGISTRY: Dict[str, Type[BaseModel]] = {
    "CustomerSupportTicket": CustomerSupportTicket,
    "FinancialSentimentReport": FinancialSentimentReport,
    "SecurityVulnerabilityAudit": SecurityVulnerabilityAudit,
    "MedicalTriageSummary": MedicalTriageSummary,
}


def get_schema_model(schema_name: str) -> Type[BaseModel]:
    if schema_name not in SCHEMA_REGISTRY:
        raise ValueError(
            f"Unknown schema '{schema_name}'. Available schemas: {list(SCHEMA_REGISTRY.keys())}"
        )
    return SCHEMA_REGISTRY[schema_name]


def get_schema_definitions() -> Dict[str, Any]:
    return {
        name: {
            "name": name,
            "json_schema": model.model_json_schema(),
            "description": model.__doc__ or name,
        }
        for name, model in SCHEMA_REGISTRY.items()
    }
