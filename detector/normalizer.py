"""
Input Normalizer

Strips character-level evasion before pattern matching runs.
This component is adversarially contested — every time a new evasion technique
surfaces in the wild, this is the first update target.

Three normalization passes (in order):
1. Whitespace collapsing — catches `i g n o r e  p r e v i o u s`
2. Zero-width character removal — catches U+200B, U+200C, U+200D, U+FEFF
3. Homoglyph mapping — catches Cyrillic lookalikes (see FAILURES.md FAIL-001)

Why a separate class: normalization needs to be testable independently.
A bug in the normalizer that causes false negatives is worse than a missing
pattern — it undermines every pattern rule simultaneously.
"""

import re
import unicodedata


# Cyrillic homoglyph → ASCII mapping
# Extended as new homoglyph abuse is identified in the wild
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "r",  # р → r
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0440": "r",  # р → r
    "\u0456": "i",  # і → i
    "\u0458": "j",  # ј → j
    "\u0455": "s",  # ѕ → s
    "\u0446": "c",  # ц (partial lookalike)
    # Greek → Latin
    "\u03bf": "o",  # ο → o
    "\u03b1": "a",  # α → a
    "\u03b5": "e",  # ε → e
    "\u03b9": "i",  # ι → i
    # Mathematical variants (bold, italic, fraktur ASCII)
    "\U0001d41a": "a",  # 𝐚 → a
    "\U0001d41e": "e",  # 𝐞 → e
    "\U0001d428": "o",  # 𝐨 → o
}

# Zero-width and invisible characters
_ZERO_WIDTH_PATTERN = re.compile(
    "["
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\ufeff"  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u00ad"  # SOFT HYPHEN
    "\u2060"  # WORD JOINER
    "\u180e"  # MONGOLIAN VOWEL SEPARATOR
    "]"
)


class InputNormalizer:
    """
    Normalizes LLM input to strip character-level injection evasion.

    Preserves original text — normalization is applied to a copy.
    Original text is retained for audit logging (logs must show what the
    user actually sent, not the normalized form).
    """

    def normalize(self, text: str) -> str:
        """
        Apply all normalization passes and return the cleaned text.

        Passes are order-dependent: zero-width removal before whitespace
        collapsing ensures that `i\u200bg\u200bn\u200bo\u200br\u200be`
        collapses to `ignore` rather than leaving invisible-char artifacts.

        Pass 4.5 handles letter-by-letter whitespace evasion:
        "i g n o r e  p r e v i o u s" → "ignore previous"
        Detects when >50% of tokens are single characters (evasion signal)
        and collapses them.
        """
        normalized = text

        # Pass 1: Remove zero-width / invisible characters
        normalized = _ZERO_WIDTH_PATTERN.sub("", normalized)

        # Pass 2: Homoglyph substitution
        normalized = self._replace_homoglyphs(normalized)

        # Pass 3: NFKC Unicode normalization (decomposes compatibility forms)
        normalized = unicodedata.normalize("NFKC", normalized)

        # Pass 4: Letter-by-letter whitespace evasion collapse
        # "i g n o r e" → "ignore"
        normalized = self._collapse_spaced_letters(normalized)

        # Pass 5: Whitespace normalization (collapse runs, strip padding)
        normalized = re.sub(r"\s+", " ", normalized).strip()

        return normalized

    @staticmethod
    def _collapse_spaced_letters(text: str) -> str:
        """
        Detect and collapse letter-by-letter whitespace evasion.

        Signal: sequence of 6+ single-character tokens (allows short acronyms).
        Example: "i g n o r e   p r e v i o u s" → "ignore   previous"

        Conservative threshold — only collapses when long runs of single chars
        are detected, to avoid collapsing legitimate acronyms or spaced words.
        """
        # Match runs of single letters separated by spaces (6+ chars minimum)
        pattern = re.compile(r"(?<!\w)([A-Za-z] ){5,}[A-Za-z](?!\w)")

        def collapse_match(m: re.Match) -> str:
            return m.group(0).replace(" ", "")

        return pattern.sub(collapse_match, text)

    @staticmethod
    def _replace_homoglyphs(text: str) -> str:
        """Replace known visual lookalikes with their ASCII equivalents."""
        result = []
        for char in text:
            result.append(_HOMOGLYPH_MAP.get(char, char))
        return "".join(result)
