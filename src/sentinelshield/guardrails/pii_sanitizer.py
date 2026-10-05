import re
import hashlib
from typing import Dict, List, Tuple, Any, Optional
from pydantic import BaseModel, Field


def luhn_checksum_valid(card_number: str) -> bool:
    """Validate credit card number using the Luhn algorithm"""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Reverse digits
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class PIITokenMap(BaseModel):
    """Ephemeral in-memory map storing reversible tokens for a single request lifetime"""
    token_to_raw: Dict[str, str] = Field(default_factory=dict)
    raw_to_token: Dict[str, str] = Field(default_factory=dict)
    counts: Dict[str, int] = Field(default_factory=dict)
    hashes: List[str] = Field(default_factory=list)


class PIIScrubResult(BaseModel):
    sanitized_text: str
    pii_found: bool
    entities_detected: Dict[str, int]
    token_map: Dict[str, str]
    audit_hashes: List[str]


# Compiled RegEx patterns for Zero-Trust In-Memory Sanitization
REGEX_PATTERNS = {
    # SSN: Standard 3-2-4 format including test and live ranges
    "SSN": re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{15,16}\b"),
    # Names: Case-insensitive prefix followed strictly by Capitalized Proper Nouns
    "NAME_CONTEXT": re.compile(
        r"(?i:(?:name\s+is\s+|patient:?\s+|customer:?\s+|employee:?\s+|client:?\s+|user:?\s+|mr\.\s+|mrs\.\s+|ms\.\s+|dr\.\s+))([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
    ),
    "MRN": re.compile(r"(?i:(?:MRN|MED-ID|PATIENT-ID)[#:\s]+)([A-Z0-9]{6,10})\b"),
}


class PIISanitizer:
    """High-throughput In-Memory PII Sanitizer & Rehydration Engine"""

    def sanitize(self, text: str, mode: str = "tokenize") -> PIIScrubResult:
        """
        Sanitize input text strictly in memory.
        mode:
          - 'tokenize': replaces with reversible <PII_{TYPE}_{N}> tokens
          - 'redact': replaces with [REDACTED_{TYPE}]
        """
        if not text:
            return PIIScrubResult(
                sanitized_text="",
                pii_found=False,
                entities_detected={},
                token_map={},
                audit_hashes=[],
            )

        token_to_raw: Dict[str, str] = {}
        raw_to_token: Dict[str, str] = {}
        counts: Dict[str, int] = {}
        audit_hashes: List[str] = []
        sanitized = text

        # Helper to generate or reuse token
        def replace_entity(raw_val: str, entity_type: str) -> str:
            raw_val_clean = raw_val.strip()
            if raw_val_clean in raw_to_token:
                return raw_to_token[raw_val_clean]

            count = counts.get(entity_type, 0) + 1
            counts[entity_type] = count

            # Hash for zero-knowledge auditing without retaining raw PII
            entity_hash = hashlib.sha256(raw_val_clean.encode()).hexdigest()[:12]
            audit_hashes.append(f"{entity_type}:{entity_hash}")

            if mode == "redact":
                token = f"[REDACTED_{entity_type}]"
            else:
                token = f"<PII_{entity_type}_{count}>"

            token_to_raw[token] = raw_val_clean
            raw_to_token[raw_val_clean] = token
            return token

        # 1. SSN
        for match in REGEX_PATTERNS["SSN"].finditer(text):
            val = match.group(0)
            token = replace_entity(val, "SSN")
            sanitized = sanitized.replace(val, token)

        # 2. Credit Cards (with Luhn check)
        for match in REGEX_PATTERNS["CREDIT_CARD"].finditer(text):
            val = match.group(0)
            digits_only = re.sub(r"\D", "", val)
            if luhn_checksum_valid(digits_only):
                token = replace_entity(val, "CREDIT_CARD")
                sanitized = sanitized.replace(val, token)

        # 3. Email
        for match in REGEX_PATTERNS["EMAIL"].finditer(text):
            val = match.group(0)
            token = replace_entity(val, "EMAIL")
            sanitized = sanitized.replace(val, token)

        # 4. Phone
        for match in REGEX_PATTERNS["PHONE"].finditer(text):
            val = match.group(0)
            # Avoid replacing if it's already part of SSN or IP
            if not any(val in ssn for ssn in raw_to_token.keys()):
                token = replace_entity(val, "PHONE")
                sanitized = sanitized.replace(val, token)

        # 5. IPv4
        for match in REGEX_PATTERNS["IPV4"].finditer(text):
            val = match.group(0)
            if val not in ["127.0.0.1", "0.0.0.0"]:  # keep standard loopbacks
                token = replace_entity(val, "IP_ADDRESS")
                sanitized = sanitized.replace(val, token)

        # 6. Names in context
        for match in REGEX_PATTERNS["NAME_CONTEXT"].finditer(text):
            full_match = match.group(0)
            name_val = match.group(1)
            token = replace_entity(name_val, "NAME")
            # Replace only the name part
            replacement = full_match.replace(name_val, token)
            sanitized = sanitized.replace(full_match, replacement)

        # 7. Medical Record Number
        for match in REGEX_PATTERNS["MRN"].finditer(text):
            full_match = match.group(0)
            mrn_val = match.group(1)
            token = replace_entity(mrn_val, "MRN")
            replacement = full_match.replace(mrn_val, token)
            sanitized = sanitized.replace(full_match, replacement)

        pii_found = len(token_to_raw) > 0

        return PIIScrubResult(
            sanitized_text=sanitized,
            pii_found=pii_found,
            entities_detected=counts,
            token_map=token_to_raw,
            audit_hashes=audit_hashes,
        )

    def rehydrate(self, data: Any, token_map: Dict[str, str]) -> Any:
        """
        Recursively replaces <PII_...> tokens with their original values in
        strings, dicts, or lists before returning data to the authorized caller.
        """
        if not token_map:
            return data

        if isinstance(data, str):
            res = data
            for token, raw_val in token_map.items():
                res = res.replace(token, raw_val)
            return res
        elif isinstance(data, dict):
            return {k: self.rehydrate(v, token_map) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.rehydrate(item, token_map) for item in data]
    def get_redaction_map(self, token_map: Dict[str, str]) -> Dict[str, str]:
        """Convert <PII_TYPE_N> tokens to [REDACTED_TYPE] without truncating multi-word types"""
        redact_map = {}
        for token in token_map:
            m = re.match(r"<PII_([A-Z0-9_]+)_\d+>", token)
            if m:
                redact_map[token] = f"[REDACTED_{m.group(1)}]"
            else:
                redact_map[token] = "[REDACTED]"
        return redact_map


pii_engine = PIISanitizer()
