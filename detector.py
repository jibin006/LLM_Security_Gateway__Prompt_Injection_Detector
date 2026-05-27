"""
LLM Security Gateway — Prompt Injection Detector

Synchronous pre-processing layer. Runs before every inference request.
Design constraints: latency budget 5ms max, fail-closed on unhealthy state.

Architecture position:
    API Gateway → Model Armor → [THIS] → Vertex AI Endpoint → Output Filter

See DECISIONS.md for reasoning on pattern-vs-embedding choice and fail-closed behavior.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .normalizer import InputNormalizer


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class AttackCategory(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_MANIPULATION = "role_manipulation"
    DATA_EXFILTRATION = "data_exfiltration"
    ENCODING_EVASION = "encoding_evasion"
    DELIMITER_INJECTION = "delimiter_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INDIRECT_INJECTION = "indirect_injection"


@dataclass
class DetectionResult:
    is_malicious: bool
    severity: Severity
    category: Optional[AttackCategory]
    matched_pattern: Optional[str]
    confidence: float
    latency_ms: float
    input_length: int
    details: str = ""
    source: str = "user_input"  # "user_input" | "rag_context"

    def to_dict(self) -> dict:
        return {
            "is_malicious": self.is_malicious,
            "severity": self.severity.value,
            "category": self.category.value if self.category else None,
            "matched_pattern": self.matched_pattern,
            "confidence": self.confidence,
            "latency_ms": round(self.latency_ms, 3),
            "input_length": self.input_length,
            "details": self.details,
            "source": self.source,
        }


@dataclass
class PatternRule:
    name: str
    pattern: re.Pattern
    category: AttackCategory
    severity: Severity
    confidence: float
    description: str


class PromptInjectionDetector:
    """
    Pattern-based prompt injection detector.

    Two detection mechanisms:
    1. Regex pattern matching — OWASP-aligned attack signatures (13 rules, 7 categories)
    2. Structural heuristics — anomaly signals that survive pattern evasion

    Normalization runs first on every input to strip character-level evasion
    (zero-width chars, homoglyphs, whitespace manipulation) before pattern matching.

    Fail-closed: if _healthy is False, every request returns is_malicious=True.
    This is intentional. See DECISIONS.md ADR-002.

    RAG context scanning: analyze_context() applies the full pipeline to
    retrieved chunks before prompt template assembly. Indirect injection
    via poisoned documents is invisible to input-only detection.
    """

    def __init__(self):
        self._normalizer = InputNormalizer()
        self._patterns = self._build_pattern_rules()
        self._heuristic_thresholds = {
            "max_input_length": 5000,
            "delimiter_density_threshold": 0.08,
            "min_length_for_delimiter_check": 100,
            "suspicious_unicode_threshold": 3,
            "repetition_threshold": 0.4,
        }
        self._healthy = True

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def analyze(self, text: str, source: str = "user_input") -> DetectionResult:
        """
        Analyze a single input for prompt injection.

        Args:
            text: Raw input text (user prompt or RAG chunk)
            source: Origin tag for audit logging ("user_input" or "rag_context")

        Returns:
            DetectionResult with is_malicious, severity, latency, category, source.

        Fail-closed: if detector is unhealthy, returns is_malicious=True unconditionally.
        """
        start = time.perf_counter()

        # Fail-closed path — see ADR-002
        if not self._healthy:
            return DetectionResult(
                is_malicious=True,
                severity=Severity.CRITICAL,
                category=None,
                matched_pattern="detector_unhealthy",
                confidence=1.0,
                latency_ms=0.0,
                input_length=len(text) if text else 0,
                details="Detector unhealthy. Fail-closed: all requests blocked.",
                source=source,
            )

        if not text or not text.strip():
            return self._safe_result(0, time.perf_counter() - start, source)

        normalized = self._normalizer.normalize(text)

        # Pattern matching
        pattern_result = self._run_pattern_matching(normalized, source)
        if pattern_result:
            pattern_result.latency_ms = (time.perf_counter() - start) * 1000
            return pattern_result

        # Heuristic analysis
        heuristic_result = self._run_heuristics(text, normalized, source)
        if heuristic_result:
            heuristic_result.latency_ms = (time.perf_counter() - start) * 1000
            return heuristic_result

        return self._safe_result(len(text), (time.perf_counter() - start) * 1000, source)

    def analyze_context(self, rag_chunks: list[str]) -> list[DetectionResult]:
        """
        Scan RAG-retrieved documents for indirect injection.

        Integration point: AFTER vector_db.search(), BEFORE prompt template assembly.

        Usage:
            chunks = vector_db.search(user_query)
            results = detector.analyze_context(chunks)
            safe_chunks = [c for c, r in zip(chunks, results) if not r.is_malicious]
            prompt = template.format(context=safe_chunks, query=user_query)

        Why this matters:
            The user's query can be completely benign. The retrieved document can
            contain malicious instructions embedded by an attacker who poisoned the
            document store. Input-only scanning sees nothing — the user's query is clean.
            This method scans the retrieval results as untrusted input.

        See FAILURES.md FAIL-004 for how this gap was discovered.
        """
        return [self.analyze(chunk, source="rag_context") for chunk in rag_chunks]

    def set_healthy(self, healthy: bool) -> None:
        """Toggle fail-closed behavior. Used by health probe and graceful shutdown."""
        self._healthy = healthy

    # -------------------------------------------------------------------------
    # Pattern Rules
    # -------------------------------------------------------------------------

    def _build_pattern_rules(self) -> list[PatternRule]:
        """
        13 rules across 7 OWASP-aligned attack categories.

        Pattern selection rationale: OWASP LLM Top 10 + public prompt injection
        research. Each pattern maps to a specific attack category. Severity reflects
        potential impact, not pattern specificity — instruction override is CRITICAL
        because it can completely hijack model behavior, not because it's uncommon.
        """
        return [
            # ---- INSTRUCTION_OVERRIDE ----
            PatternRule(
                name="ignore_instructions",
                pattern=re.compile(
                    r"ignore\s+(all\s+)?(previous|prior|above|earlier|initial|original)\s+"
                    r"(instructions?|prompts?|rules?|guidelines?|directives?|system\s+prompt)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description="Classic instruction override — attempts to nullify system prompt",
            ),
            PatternRule(
                name="disregard_instructions",
                pattern=re.compile(
                    r"(disregard|override|circumvent|violate)\s+(\w+\s+){0,3}"
                    r"(instructions?|rules?|guidelines?|constraints?|limitations?|restrictions?|safety|filter)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                severity=Severity.CRITICAL,
                confidence=0.90,
                description="Disregard/override instruction family — allows filler words between verb and target",
            ),
            PatternRule(
                name="new_instructions",
                pattern=re.compile(
                    r"(new|updated?|revised?|actual|real|true)\s+(instructions?|rules?|system\s+prompt|directives?)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                severity=Severity.HIGH,
                confidence=0.75,
                description="Fake instruction replacement — pretends to inject new system rules",
            ),
            # ---- ROLE_MANIPULATION ----
            PatternRule(
                name="you_are_now",
                pattern=re.compile(
                    r"you\s+are\s+now\s+((a|an|the)\s+)?\w+",
                    re.IGNORECASE,
                ),
                category=AttackCategory.ROLE_MANIPULATION,
                severity=Severity.CRITICAL,
                confidence=0.88,
                description="Role reassignment — attempts to redefine model identity. No article required (catches 'You are now DAN').",
            ),
            PatternRule(
                name="pretend_roleplay",
                pattern=re.compile(
                    r"(pretend|act|roleplay|imagine|assume|behave)\s+(you\s+are|to\s+be|as\s+if|like\s+you\s+are)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.ROLE_MANIPULATION,
                severity=Severity.HIGH,
                confidence=0.80,
                description="Roleplay-based identity override",
            ),
            PatternRule(
                name="jailbreak_mode",
                pattern=re.compile(
                    r"(jailbreak|unrestricted|uncensored|dan|dna|evil|god)\s*mode|"
                    r"developer\s+mode\s+.{0,30}(no\s+restrict|unlimit|unrestrict|no\s+limit|bypass)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.ROLE_MANIPULATION,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description=(
                    "Named jailbreak mode activation. 'developer mode' only triggers when paired with "
                    "restriction-removal context — avoids FP on 'React DevTools developer mode toggle'."
                ),
            ),
            # ---- SYSTEM_PROMPT_EXTRACTION ----
            PatternRule(
                name="reveal_system_prompt",
                pattern=re.compile(
                    r"(reveal|show|print|output|display|repeat|tell\s+me|what\s+is|share)\s+"
                    r"(\w+\s+){0,3}"
                    r"(system\s+prompt|initial\s+instructions?|original\s+instructions?|"
                    r"prompt\s+template|instructions?\s+you\s+(were|have\s+been)\s+(given|told|configured))",
                    re.IGNORECASE,
                ),
                category=AttackCategory.SYSTEM_PROMPT_EXTRACTION,
                severity=Severity.HIGH,
                confidence=0.85,
                description=(
                    "System prompt extraction. Up to 3 filler words allowed between trigger verb "
                    "and target phrase — catches 'Show me your initial instructions and...' patterns."
                ),
            ),
            # ---- DATA_EXFILTRATION ----
            PatternRule(
                name="data_exfil_request",
                pattern=re.compile(
                    r"(exfiltrate|leak|expose)\s+.{0,30}"
                    r"(all\s+)?(data|information|records?|documents?|files?|contents?|credentials?)|"
                    r"(output|transmit|send)\s+all\s+.{0,20}"
                    r"(data|information|records?|documents?|files?|credentials?)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.DATA_EXFILTRATION,
                severity=Severity.MEDIUM,
                confidence=0.70,
                description=(
                    "Data exfiltration pattern. Narrowed from 'extract/dump + data' to reduce FP rate. "
                    "Previous version triggered on 'extract data from CSV' and 'dump database schema'. "
                    "Current version requires 'all' qualifier with output/send, or explicit exfil vocabulary."
                ),
            ),
            # ---- ENCODING_EVASION ----
            PatternRule(
                name="base64_injection",
                pattern=re.compile(
                    r"(decode|base64|hex|rot13|caesar|cipher).{0,60}"
                    r"(execute|run|follow|apply|process|carry\s+out)",
                    re.IGNORECASE | re.DOTALL,
                ),
                category=AttackCategory.ENCODING_EVASION,
                severity=Severity.HIGH,
                confidence=0.85,
                description="Encoding-then-execute — catches non-adjacent 'decode...execute' with up to 60 chars between",
            ),
            # ---- DELIMITER_INJECTION ----
            PatternRule(
                name="fake_system_block",
                pattern=re.compile(
                    r"(\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>|\[ADMIN\]|\[ROOT\]|"
                    r"\[OVERRIDE\]|<<SYS>>|###\s*SYSTEM|---\s*SYSTEM)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.DELIMITER_INJECTION,
                severity=Severity.HIGH,
                confidence=0.90,
                description="Fake system/instruction delimiter injection — attempts to create synthetic context boundaries",
            ),
            # ---- CONTEXT_MANIPULATION ----
            PatternRule(
                name="above_text_is_fake",
                pattern=re.compile(
                    r"(the\s+)?(above|previous|prior)\s+(text|content|context|information|instructions?)\s+"
                    r"(is|are|was|were)\s+(fake|false|wrong|incorrect|not\s+real|irrelevant)",
                    re.IGNORECASE,
                ),
                category=AttackCategory.CONTEXT_MANIPULATION,
                severity=Severity.HIGH,
                confidence=0.85,
                description="Context invalidation — attempts to nullify retrieved context or prior conversation",
            ),
            # ---- INDIRECT_INJECTION ----
            PatternRule(
                name="embedded_system_update",
                pattern=re.compile(
                    r"(SYSTEM\s+UPDATE|IMPORTANT\s+UPDATE|ADMIN\s+MESSAGE|SECURITY\s+NOTICE)\s*:"
                    r".{0,100}(disregard|ignore|bypass|override)",
                    re.IGNORECASE | re.DOTALL,
                ),
                category=AttackCategory.INDIRECT_INJECTION,
                severity=Severity.CRITICAL,
                confidence=0.92,
                description="RAG document poisoning — embedded system-update-style instruction in document content",
            ),
            PatternRule(
                name="doc_note_to_ai",
                pattern=re.compile(
                    r"(note\s+to\s+(ai|llm|model|assistant|chatbot)|ai\s+instruction|model\s+note)\s*:",
                    re.IGNORECASE,
                ),
                category=AttackCategory.INDIRECT_INJECTION,
                severity=Severity.HIGH,
                confidence=0.88,
                description="Document-embedded AI instruction — disguised as inline document note",
            ),
        ]

    # -------------------------------------------------------------------------
    # Detection Pipeline
    # -------------------------------------------------------------------------

    def _run_pattern_matching(
        self, normalized_text: str, source: str
    ) -> Optional[DetectionResult]:
        for rule in self._patterns:
            match = rule.pattern.search(normalized_text)
            if match:
                return DetectionResult(
                    is_malicious=True,
                    severity=rule.severity,
                    category=rule.category,
                    matched_pattern=rule.name,
                    confidence=rule.confidence,
                    latency_ms=0.0,  # caller fills in
                    input_length=len(normalized_text),
                    details=f"{rule.description}. Matched: '{match.group(0)[:80]}'",
                    source=source,
                )
        return None

    def _run_heuristics(
        self, original_text: str, normalized_text: str, source: str
    ) -> Optional[DetectionResult]:
        """
        Structural anomaly detection — catches attacks that survive pattern matching.

        Four signals:
        1. Prompt stuffing: token flooding to manipulate attention weights
        2. Delimiter density: suspiciously high density of context-boundary markers
        3. Suspicious Unicode: evasion characters surviving normalization
        4. Instruction repetition: repeated directive-style phrases

        Thresholds calibrated against benign corpus — see FAILURES.md FAIL-003.
        """
        # 1. Prompt stuffing / token flooding
        if len(original_text) > self._heuristic_thresholds["max_input_length"]:
            return DetectionResult(
                is_malicious=True,
                severity=Severity.HIGH,
                category=AttackCategory.CONTEXT_MANIPULATION,
                matched_pattern="prompt_stuffing",
                confidence=0.75,
                latency_ms=0.0,
                input_length=len(original_text),
                details=(
                    f"Input length {len(original_text)} exceeds threshold "
                    f"{self._heuristic_thresholds['max_input_length']}. "
                    "Token flooding can manipulate attention weights away from system instructions."
                ),
                source=source,
            )

        # 2. Delimiter density (fake context boundary injection)
        if len(original_text) >= self._heuristic_thresholds["min_length_for_delimiter_check"]:
            delimiter_count = len(re.findall(r"[-=*#|<>\[\]{}]{3,}", original_text))
            density = delimiter_count / len(original_text)
            if density > self._heuristic_thresholds["delimiter_density_threshold"]:
                return DetectionResult(
                    is_malicious=True,
                    severity=Severity.HIGH,
                    category=AttackCategory.DELIMITER_INJECTION,
                    matched_pattern="delimiter_density",
                    confidence=0.70,
                    latency_ms=0.0,
                    input_length=len(original_text),
                    details=(
                        f"Delimiter density {density:.3f} exceeds threshold "
                        f"{self._heuristic_thresholds['delimiter_density_threshold']}. "
                        "High delimiter density used to create fake context boundaries."
                    ),
                    source=source,
                )

        # 3. Suspicious Unicode (post-normalization residue)
        suspicious_chars = [
            c for c in original_text
            if unicodedata.category(c) in ("Cf", "Mn") and ord(c) > 127
        ]
        if len(suspicious_chars) > self._heuristic_thresholds["suspicious_unicode_threshold"]:
            return DetectionResult(
                is_malicious=True,
                severity=Severity.HIGH,
                category=AttackCategory.ENCODING_EVASION,
                matched_pattern="suspicious_unicode",
                confidence=0.80,
                latency_ms=0.0,
                input_length=len(original_text),
                details=(
                    f"Found {len(suspicious_chars)} suspicious Unicode characters "
                    f"(categories Cf/Mn, non-ASCII). "
                    "Potential invisible character injection or homoglyph evasion residue."
                ),
                source=source,
            )

        # 4. Instruction repetition (directive flooding)
        directive_words = re.findall(
            r"\b(ignore|disregard|forget|override|bypass|pretend|roleplay)\b",
            normalized_text,
            re.IGNORECASE,
        )
        word_count = len(normalized_text.split())
        if word_count > 0 and len(directive_words) / word_count > self._heuristic_thresholds["repetition_threshold"]:
            return DetectionResult(
                is_malicious=True,
                severity=Severity.HIGH,
                category=AttackCategory.INSTRUCTION_OVERRIDE,
                matched_pattern="directive_repetition",
                confidence=0.72,
                latency_ms=0.0,
                input_length=len(original_text),
                details=(
                    f"Directive word density {len(directive_words) / word_count:.3f} "
                    f"exceeds repetition threshold. "
                    "Repeated override directives suggest instruction manipulation attempt."
                ),
                source=source,
            )

        return None

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _safe_result(input_length: int, elapsed: float, source: str) -> DetectionResult:
        return DetectionResult(
            is_malicious=False,
            severity=Severity.SAFE,
            category=None,
            matched_pattern=None,
            confidence=1.0,
            latency_ms=elapsed * 1000,
            input_length=input_length,
            details="No injection pattern detected.",
            source=source,
        )
