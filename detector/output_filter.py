"""
LLM Security Gateway — Output Filter

Post-inference layer. Runs on every model response before it reaches the client.
Handles two failure modes that input detection can't prevent:

1. PII in model response — model may have memorized training data containing
   credentials or personal data, or indirect injection may have partially succeeded
   and caused exfiltration through a legitimate-looking response.

2. System prompt leak — if an injection partially succeeds and the model begins
   revealing its system prompt, this is the last catch before client sees it.

Design: deterministic, regex-based. Adding latency budget: 1–3ms per response.
No external calls, no model inference. Must not fail — if this throws, the response
is blocked, not passed through.

Coverage per deployment context:
    AWS + GCP (multi-cloud): both AWS access key and GCP SA key patterns included.
    Rationale: model trained on internal runbooks may have seen credentials in both
    formats embedded in code examples. See FAILURES.md FAIL-006.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional


# ---- PII Redaction Patterns ----

_PII_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "ssn",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        "[REDACTED-SSN]",
    ),
    (
        "credit_card",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"      # Visa
            r"5[1-5][0-9]{14}|"                     # Mastercard
            r"3[47][0-9]{13}|"                      # Amex
            r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"     # Diners
            r"6(?:011|5[0-9]{2})[0-9]{12})\b"       # Discover
        ),
        "[REDACTED-CC]",
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
        "[REDACTED-EMAIL]",
    ),
    (
        "us_phone",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?"
            r"(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?"
            r"[2-9]\d{2}[-.\s]?\d{4}\b"
        ),
        "[REDACTED-PHONE]",
    ),
    (
        "ip_address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "[REDACTED-IP]",
    ),
    (
        "aws_access_key",
        re.compile(r"\b(AKIA|AIPA|AROA|ASIA)[A-Z0-9]{16}\b"),
        "[REDACTED-AWS-KEY]",
    ),
    (
        "aws_secret_key",
        re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "[REDACTED-AWS-SECRET]",
    ),
    (
        "gcp_api_key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "[REDACTED-GCP-APIKEY]",
    ),
    (
        "gcp_sa_private_key",
        re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        "[REDACTED-GCP-SA-KEY]",
    ),
]


# ---- System Leak Detection Patterns ----

_SYSTEM_LEAK_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "system_prompt_reveal",
        re.compile(
            r"(my\s+system\s+prompt\s+(is|says?|reads?|contains?)|"
            r"i\s+was\s+instructed\s+to|"
            r"my\s+instructions?\s+(are|say|tell\s+me|require)|"
            r"i\s+am\s+configured\s+to|"
            r"the\s+system\s+prompt\s+(is|says?|reads?|starts?))",
            re.IGNORECASE,
        ),
    ),
    (
        "internal_path_exposure",
        re.compile(
            r"(/etc/|/var/|/home/|/usr/local/|/opt/|"
            r"C:\\Users\\|C:\\Windows\\|C:\\Program Files\\|"
            r"\\\\internal\.|\.corp\.|\.internal\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "template_variable_leak",
        re.compile(r"\{\{[^}]+\}\}|\{[A-Z_]{3,}\}"),  # Jinja2-style / env var style
    ),
]


@dataclass
class FilterResult:
    original: str
    filtered: str
    redacted_types: list[str] = field(default_factory=list)
    system_leaks_detected: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    @property
    def was_modified(self) -> bool:
        return self.original != self.filtered

    @property
    def has_system_leak(self) -> bool:
        return len(self.system_leaks_detected) > 0

    def to_dict(self) -> dict:
        return {
            "was_modified": self.was_modified,
            "has_system_leak": self.has_system_leak,
            "redacted_types": self.redacted_types,
            "system_leaks_detected": self.system_leaks_detected,
            "latency_ms": round(self.latency_ms, 3),
            "filtered_response": self.filtered,
        }


class OutputFilter:
    """
    Post-inference response sanitizer.

    Two passes:
    1. PII redaction — deterministic substitution, preserves response structure
    2. System information leak detection — flags (does not redact, for auditability)

    On any exception: block the response entirely (fail-closed).
    The caller should catch FilterError and return a generic error to the client.

    This component cannot retry — it either runs clean or blocks.
    """

    def filter(self, response_text: str) -> FilterResult:
        """
        Apply PII redaction and system leak detection to a model response.

        Returns FilterResult with the sanitized text and audit metadata.
        On internal error, raises FilterError — caller must handle.
        """
        start = time.perf_counter()

        try:
            filtered_text, redacted_types = self._redact_pii(response_text)
            system_leaks = self._detect_system_leaks(filtered_text)

            return FilterResult(
                original=response_text,
                filtered=filtered_text,
                redacted_types=redacted_types,
                system_leaks_detected=system_leaks,
                latency_ms=(time.perf_counter() - start) * 1000,
            )
        except Exception as exc:
            raise FilterError(f"Output filter failed: {exc}") from exc

    def _redact_pii(self, text: str) -> tuple[str, list[str]]:
        """
        Apply all PII redaction patterns sequentially.

        Returns (redacted_text, list_of_redacted_types).
        Pattern application is idempotent — running twice produces the same result.
        """
        redacted_types: list[str] = []
        current = text

        for pattern_name, pattern, replacement in _PII_PATTERNS:
            new_text = pattern.sub(replacement, current)
            if new_text != current:
                redacted_types.append(pattern_name)
                current = new_text

        return current, redacted_types

    def _detect_system_leaks(self, text: str) -> list[str]:
        """
        Detect if model response contains system prompt disclosure or internal paths.

        Detection only — does not redact. Audit logging is the action here.
        A partially successful injection that caused system prompt reveal should be
        captured as a security event with the full original response, not silently stripped.
        """
        detected: list[str] = []
        for leak_name, pattern in _SYSTEM_LEAK_PATTERNS:
            if pattern.search(text):
                detected.append(leak_name)
        return detected


class FilterError(Exception):
    """Raised when output filter fails internally. Caller should block the response."""
    pass
