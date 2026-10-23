"""Run a policy against a breach corpus and collect statistics.

The analyzer streams the wordlist line by line, so it handles multi-gigabyte
corpora (e.g. the full 14M-line rockyou.txt) without loading them into memory.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .policy import Policy, char_classes


@dataclass
class AnalysisResult:
    policy: Policy
    total: int = 0                       # passwords examined
    compliant: int = 0                   # breach passwords the policy ALLOWS
    rejected: int = 0                    # breach passwords the policy blocks
    length_hist: Counter = field(default_factory=Counter)
    class_count_hist: Counter = field(default_factory=Counter)
    failure_reasons: Counter = field(default_factory=Counter)
    sample_compliant: list[str] = field(default_factory=list)

    @property
    def compliant_rate(self) -> float:
        """Fraction of the breach that would still pass the policy (0..1).

        Higher is WORSE: it is the share of already-leaked passwords the policy
        fails to stop.
        """
        return self.compliant / self.total if self.total else 0.0

    @property
    def rejected_rate(self) -> float:
        return self.rejected / self.total if self.total else 0.0


def iter_passwords(path: str | Path) -> Iterator[str]:
    """Yield passwords from a wordlist, tolerating the usual encoding mess."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            pw = line.rstrip("\n").rstrip("\r")
            if pw:
                yield pw


def analyze(
    policy: Policy,
    passwords: Iterable[str],
    *,
    sample_limit: int = 20,
    limit: int | None = None,
) -> AnalysisResult:
    """Evaluate ``policy`` against an iterable of ``passwords``.

    ``limit`` caps how many passwords are examined (useful for a quick run on a
    weak machine); ``sample_limit`` caps how many example compliant passwords
    are retained for the report.
    """
    result = AnalysisResult(policy=policy)
    for i, pw in enumerate(passwords):
        if limit is not None and i >= limit:
            break
        result.total += 1
        present = char_classes(pw)  # computed once, reused by evaluate() below
        result.length_hist[len(pw)] += 1
        result.class_count_hist[len(present)] += 1

        passes, reasons = policy.evaluate(pw, present)
        if passes:
            result.compliant += 1
            if len(result.sample_compliant) < sample_limit:
                result.sample_compliant.append(pw)
        else:
            result.rejected += 1
            for reason in reasons:
                # Normalise the numeric detail out of the reason for grouping.
                key = reason.split(" (")[0]
                result.failure_reasons[key] += 1
    return result
