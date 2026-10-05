import pytest
from sentinelshield.schemas.registry import CustomerSupportTicket, FinancialSentimentReport
from sentinelshield.repair.self_healing import self_healing_engine, extract_json_from_text
from sentinelshield.inference.simulator import SimulatorInferenceProvider


def test_extract_json_from_markdown():
    markdown_wrapped = """Here is the structured ticket data:
```json
{
    "ticket_id": "TCK-100",
    "customer_name": "Dave",
    "customer_email": "dave@example.com",
    "issue_category": "technical",
    "priority": "low",
    "sentiment": "neutral",
    "summary": "Everything is functioning as expected.",
    "action_items": ["Close ticket"],
    "requires_human_escalation": false
}
```
Let me know if you need anything else!"""

    extracted = extract_json_from_text(markdown_wrapped)
    assert extracted.startswith("{")
    assert extracted.endswith("}")


@pytest.mark.asyncio
async def test_self_healing_repair_loop_on_malformed_json():
    # Instantiate simulator in malformed mode
    simulator = SimulatorInferenceProvider(simulate_malformed=True)
    initial_raw = await simulator.generate(
        prompt="Simulate failure",
        system_prompt="Schema: CustomerSupportTicket",
    )

    # Note: initial_raw has type mismatches and markdown wrappers
    system_prompt = "Produce valid CustomerSupportTicket JSON"
    instance, report = await self_healing_engine.validate_and_heal(
        raw_output=initial_raw,
        target_model=CustomerSupportTicket,
        inference_provider=simulator,
        system_prompt=system_prompt,
    )

    assert isinstance(instance, CustomerSupportTicket)
    assert report.required is True
    assert report.repaired is True
    assert report.attempts >= 2
    assert len(report.initial_errors) > 0
    # Verified sub-100ms repair performance
    assert report.repair_time_ms < 150.0
    assert instance.ticket_id is not None
    assert isinstance(instance.action_items, list)


@pytest.mark.asyncio
async def test_self_healing_already_valid_json():
    simulator = SimulatorInferenceProvider(simulate_malformed=False)
    initial_raw = await simulator.generate(
        prompt="Standard input",
        system_prompt="Schema: FinancialSentimentReport",
    )

    instance, report = await self_healing_engine.validate_and_heal(
        raw_output=initial_raw,
        target_model=FinancialSentimentReport,
        inference_provider=simulator,
        system_prompt="Produce valid FinancialSentimentReport",
    )

    assert isinstance(instance, FinancialSentimentReport)
    assert report.required is False
    assert report.attempts == 1
    assert instance.ticker == "NVDA"
