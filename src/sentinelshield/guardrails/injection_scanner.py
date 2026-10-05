import re
import unicodedata
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field

from sentinelshield.config import settings


class InjectionScanResult(BaseModel):
    is_safe: bool = Field(..., description="Whether the prompt is considered safe to execute")
    threat_level: str = Field(..., description="CLEAN, LOW, MEDIUM, HIGH, CRITICAL")
    risk_score: float = Field(..., description="Risk score from 0.0 (safe) to 1.0 (dangerous)")
    detected_patterns: List[str] = Field(default_factory=list, description="List of matched injection patterns")
    action_taken: str = Field(..., description="ALLOW, SANITIZE, or BLOCK")
    reason: str = Field(..., description="Human-readable explanation of the verdict")


# High-confidence adversarial injection signatures
SIGNATURE_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
    # Direct instruction override
    (
        "DirectInstructionOverride",
        re.compile(
            r"(ignore|disregard|forget|bypass|override|drop)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|commands|constraints)",
            re.IGNORECASE,
        ),
        0.95,
    ),
    (
        "SystemPromptExfiltration",
        re.compile(
            r"(repeat|print|reveal|output|display|dump|leak)\s+(the\s+)?(system\s+prompt|initial\s+instructions|system\s+instructions|developer\s+prompt|context\s+above)",
            re.IGNORECASE,
        ),
        0.90,
    ),
    # Persona / Jailbreak modes
    (
        "JailbreakPersonaTrigger",
        re.compile(
            r"(you\s+are\s+now|pretend\s+to\s+be|act\s+as|roleplay\s+as)\s+(DAN|unfiltered|jailbroken|evil\s+bot|anarchist|do\s+anything\s+now|developer\s+mode)",
            re.IGNORECASE,
        ),
        0.88,
    ),
    (
        "SecurityConstraintBypass",
        re.compile(
            r"(disable|turn\s+off|bypass|suspend)\s+(content\s+filter|safety\s+filter|guardrails|safety\s+protocols|ethical\s+guidelines)",
            re.IGNORECASE,
        ),
        0.92,
    ),
    # Delimiter and special token injection
    (
        "SystemDelimiterInjection",
        re.compile(
            r"(<\|im_start\|>system|<\|endoftext\|>|\[SYSTEM\]|<<SYS>>|---BEGIN\s+SYSTEM---|role:\s*\"?system\"?)",
            re.IGNORECASE,
        ),
        0.98,
    ),
    # Base64 decode execution commands
    (
        "EncodedPayloadExecution",
        re.compile(
            r"(decode\s+the\s+following\s+base64|execute\s+this\s+base64|eval\(atob\(|from_base64)",
            re.IGNORECASE,
        ),
        0.75,
    ),
    # Coercive output forcing
    (
        "CoerciveOutputForcing",
        re.compile(
            r"(do\s+not\s+say\s+no|you\s+must\s+comply|say\s+nothing\s+except|output\s+only\s+the\s+word\s+CONFIRM)",
            re.IGNORECASE,
        ),
        0.60,
    ),
]


class InjectionScanner:
    """Enterprise Prompt Injection & Jailbreak Defense Engine"""

    def __init__(self, threshold: float = settings.PROMPT_INJECTION_THRESHOLD):
        self.threshold = threshold

    def normalize_text(self, text: str) -> str:
        """Strip invisible unicode characters and normalize NFKC encoding"""
        # Normalize unicode to standard forms (defeats lookalike / homoglyph tricks)
        normalized = unicodedata.normalize("NFKC", text)
        # Strip zero-width spaces, joiners, formatting characters
        normalized = re.sub(r"[\u200B-\u200D\uFEFF]", "", normalized)
        return normalized

    def scan(self, prompt: str) -> InjectionScanResult:
        if not prompt or not prompt.strip():
            return InjectionScanResult(
                is_safe=True,
                threat_level="CLEAN",
                risk_score=0.0,
                detected_patterns=[],
                action_taken="ALLOW",
                reason="Empty prompt is safe.",
            )

        clean_text = self.normalize_text(prompt)
        detected_patterns = []
        max_score = 0.0

        for name, pattern, score in SIGNATURE_PATTERNS:
            if pattern.search(clean_text):
                detected_patterns.append(name)
                if score > max_score:
                    max_score = score

        # Check for suspicious delimiter stacking
        delimiter_count = len(re.findall(r"[`~\"'\[\]{}|<>]", clean_text))
        if delimiter_count > 35 and len(clean_text) < 200:
            detected_patterns.append("ExcessiveDelimiterDensity")
            max_score = max(max_score, 0.70)

        # Check for system roleplay override attempt
        if re.search(r"^\s*(System|Assistant|AI):\s*", clean_text, re.MULTILINE):
            detected_patterns.append("RoleHeaderSpoofing")
            max_score = max(max_score, 0.85)

        # Determine threat level and action
        if max_score >= 0.85:
            threat_level = "CRITICAL"
            is_safe = False
            action = "BLOCK"
            reason = f"Critical adversarial prompt injection detected ({', '.join(detected_patterns)})."
        elif max_score >= self.threshold:
            threat_level = "HIGH"
            is_safe = False
            action = "BLOCK"
            reason = f"High-confidence prompt injection detected ({', '.join(detected_patterns)}). Exceeds safety threshold {self.threshold}."
        elif max_score >= 0.40:
            threat_level = "MEDIUM"
            is_safe = True
            action = "SANITIZE"
            reason = f"Suspicious patterns detected ({', '.join(detected_patterns)}). Allowed with guardrail monitoring."
        elif max_score > 0.0:
            threat_level = "LOW"
            is_safe = True
            action = "ALLOW"
            reason = "Minor anomalous pattern, benign intent inferred."
        else:
            threat_level = "CLEAN"
            is_safe = True
            action = "ALLOW"
            reason = "No prompt injection or adversarial signatures found."

        return InjectionScanResult(
            is_safe=is_safe,
            threat_level=threat_level,
            risk_score=round(max_score, 3),
            detected_patterns=detected_patterns,
            action_taken=action,
            reason=reason,
        )


scanner = InjectionScanner()
