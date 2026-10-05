import re
import json
import time
from typing import Type, Tuple, Optional, Any, List
from pydantic import BaseModel, ValidationError

from sentinelshield.schemas.base_models import SelfHealingReport
from sentinelshield.inference.base import BaseInferenceProvider


def extract_json_from_text(text: str) -> str:
    """Extract raw JSON string from markdown code blocks or surrounding text"""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start : end + 1]

    return text


def clean_json_syntax(text: str) -> str:
    """Fix minor JSON syntax errors like trailing commas before closing braces"""
    return re.sub(r",\s*([\]}])", r"\1", text)


class SelfHealingRepairEngine:
    """
    Real Self-Healing JSON Repair Loop powered by Pydantic v2 Rust validation core.
    Intercepts JSONDecodeError and pydantic.ValidationError, creates targeted
    diagnostic feedback, re-prompts the model, and verifies compliance.
    Does NOT hallucinate or fake data.
    """

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries

    async def validate_and_heal(
        self,
        raw_output: str,
        target_model: Type[BaseModel],
        inference_provider: BaseInferenceProvider,
        system_prompt: str,
        model_name: Optional[str] = None,
    ) -> Tuple[Optional[BaseModel], SelfHealingReport]:
        start_time = time.perf_counter()
        current_raw = raw_output
        report = SelfHealingReport(
            required=False,
            attempts=1,
            repaired=False,
            sub_100ms_achieved=False,
            initial_errors=[],
            re_prompt_sent=None,
            repair_time_ms=0.0,
        )

        for attempt in range(1, self.max_retries + 1):
            report.attempts = attempt
            extracted_json = extract_json_from_text(current_raw)
            cleaned_json = clean_json_syntax(extracted_json)

            # Step 1: Attempt JSON parsing
            parsed_dict = None
            try:
                parsed_dict = json.loads(cleaned_json)
            except json.JSONDecodeError as jde:
                report.required = True
                err_msg = f"JSON Syntax Error: {jde.msg} at line {jde.lineno} col {jde.colno}"
                if attempt == 1:
                    report.initial_errors.append(err_msg)

            # Step 2: Attempt Rust Pydantic v2 validation
            if parsed_dict is not None:
                try:
                    instance = target_model.model_validate(parsed_dict)
                    elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    report.repair_time_ms = round(elapsed_ms, 2)
                    report.sub_100ms_achieved = elapsed_ms < 100.0
                    if attempt > 1:
                        report.repaired = True
                    return instance, report
                except ValidationError as ve:
                    report.required = True
                    for err in ve.errors():
                        loc = ".".join(str(p) for p in err["loc"])
                        field_err = f"Field '{loc}': {err['msg']} (Input: {err.get('input', 'None')})"
                        if attempt == 1:
                            report.initial_errors.append(field_err)

            # Step 3: If validation failed and retries remain, construct precision re-prompt
            if attempt < self.max_retries:
                schema_json = json.dumps(target_model.model_json_schema(), indent=2)
                errors_summary = "\n".join(f"- {e}" for e in (report.initial_errors or ["Malformed JSON syntax"]))

                reprompt_message = f"""CRITICAL ERROR: Your previous JSON output failed Pydantic v2 validation.
Specific Validation Errors:
{errors_summary}

Target Pydantic v2 JSON Schema:
{schema_json}

Your previous output was:
{current_raw}

TASK:
Fix the schema validation errors listed above.
Respond ONLY with the corrected valid JSON object. Do not include markdown codeblocks, explanations, or preamble. Return strictly the raw JSON object."""

                report.re_prompt_sent = reprompt_message

                # Execute real re-prompt against the model
                current_raw = await inference_provider.generate(
                    prompt=reprompt_message,
                    system_prompt=system_prompt,
                    json_mode=True,
                    temperature=0.0,
                    model=model_name,
                )

        # If all retries failed, return None for instance and report failure
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        report.repair_time_ms = round(elapsed_ms, 2)
        report.repaired = False
        report.sub_100ms_achieved = False
        return None, report


self_healing_engine = SelfHealingRepairEngine()
