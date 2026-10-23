"""Password policy definition and evaluation.

A :class:`Policy` encodes the rules an organisation enforces when users choose a
password (minimum length, required character classes, etc.). The core question
this project answers is: *given a real breach corpus, how many of those already
leaked passwords would still satisfy this policy?* Every password that satisfies
it is a weak password the policy fails to stop.
"""
from __future__ import annotations

import json
import string
from dataclasses import dataclass, asdict
from pathlib import Path

# Character-class sizes used for keyspace / brute-force estimates.
CLASS_SIZES = {
    "lower": 26,
    "upper": 26,
    "digit": 10,
    "symbol": len(string.punctuation),  # 32 printable ASCII symbols
}

_LOWER = set(string.ascii_lowercase)
_UPPER = set(string.ascii_uppercase)
_DIGIT = set(string.digits)
_SYMBOL = set(string.punctuation)


def char_classes(password: str) -> set[str]:
    """Return the set of character classes present in ``password``.

    Deduplicating with ``set(password)`` first keeps this cheap on the full
    rockyou corpus: a typical password has only a handful of distinct
    characters, and ``isdisjoint`` short-circuits on the first match.
    Characters outside printable ASCII (e.g. accents) count toward length but
    not toward any class.
    """
    chars = set(password)
    classes: set[str] = set()
    if not chars.isdisjoint(_LOWER):
        classes.add("lower")
    if not chars.isdisjoint(_UPPER):
        classes.add("upper")
    if not chars.isdisjoint(_DIGIT):
        classes.add("digit")
    if not chars.isdisjoint(_SYMBOL):
        classes.add("symbol")
    return classes


@dataclass
class Policy:
    """A password policy.

    Attributes mirror the knobs most real-world policies expose. ``required_*``
    flags force a given character class to be present; ``min_char_classes``
    requires at least N distinct classes (a common NIST-era alternative to
    forcing specific ones).
    """

    min_length: int = 8
    max_length: int | None = None
    require_lower: bool = False
    require_upper: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    min_char_classes: int = 0

    def evaluate(
        self, password: str, present: set[str] | None = None
    ) -> tuple[bool, list[str]]:
        """Return ``(passes, reasons)`` where ``reasons`` lists the failures.

        ``present`` lets a caller that already computed the password's character
        classes (e.g. the analyzer, which also needs them for its histogram)
        pass them in to avoid recomputing — a measurable win over 14M rows.
        """
        reasons: list[str] = []
        length = len(password)
        if length < self.min_length:
            reasons.append(f"shorter than min_length ({length} < {self.min_length})")
        if self.max_length is not None and length > self.max_length:
            reasons.append(f"longer than max_length ({length} > {self.max_length})")

        if present is None:
            present = char_classes(password)
        if self.require_lower and "lower" not in present:
            reasons.append("missing lowercase letter")
        if self.require_upper and "upper" not in present:
            reasons.append("missing uppercase letter")
        if self.require_digit and "digit" not in present:
            reasons.append("missing digit")
        if self.require_symbol and "symbol" not in present:
            reasons.append("missing symbol")
        if self.min_char_classes and len(present) < self.min_char_classes:
            reasons.append(
                f"too few character classes ({len(present)} < {self.min_char_classes})"
            )
        return (not reasons, reasons)

    def passes(self, password: str) -> bool:
        """Convenience wrapper returning only the boolean verdict."""
        return self.evaluate(password)[0]

    def effective_charset_size(self) -> int:
        """Smallest charset an attacker must brute-force a *compliant* password with.

        This is a deliberately conservative (worst-case-for-defender) estimate:
        the weakest password the policy allows uses exactly the required classes.
        If nothing is required we assume lowercase letters only. The resulting
        keyspace is ``effective_charset_size ** min_length`` — see
        :mod:`ppa.crack_time`.
        """
        size = 0
        if self.require_lower:
            size += CLASS_SIZES["lower"]
        if self.require_upper:
            size += CLASS_SIZES["upper"]
        if self.require_digit:
            size += CLASS_SIZES["digit"]
        if self.require_symbol:
            size += CLASS_SIZES["symbol"]
        if size == 0:
            # No specific class required: assume the user picks the laziest
            # option that still meets min_char_classes, i.e. lowercase.
            size = CLASS_SIZES["lower"]
        return size

    # ----- serialisation helpers -------------------------------------------
    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        known = {f: data[f] for f in cls.__dataclass_fields__ if f in data}
        return cls(**known)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def describe(self) -> str:
        parts = [f"length >= {self.min_length}"]
        if self.max_length is not None:
            parts.append(f"length <= {self.max_length}")
        for flag, label in (
            ("require_lower", "lowercase"),
            ("require_upper", "uppercase"),
            ("require_digit", "digit"),
            ("require_symbol", "symbol"),
        ):
            if getattr(self, flag):
                parts.append(f"requires {label}")
        if self.min_char_classes:
            parts.append(f">= {self.min_char_classes} char classes")
        return "; ".join(parts)
