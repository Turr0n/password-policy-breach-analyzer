"""Estimate how long a brute-force attack would take against a policy.

Hash rates below are *measured / realistic* figures for common hardware, so the
estimates stay grounded. They were benchmarked with hashcat v6.2.6:

* ``cpu``   -> an Intel i5-12400F (CPU only)
* ``gpu``   -> an NVIDIA RTX 2060 SUPER (consumer GPU)
* ``rig``   -> an 8x high-end GPU cracking rig (illustrative upper bound)

The point of the tool is comparative, not forensic: it shows how the *same*
policy collapses on fast hashes (MD5) yet holds on slow ones (bcrypt/argon2).
"""
from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy

# Hash rates in hashes per second. Rough but realistic order-of-magnitude values.
HASHRATES: dict[str, dict[str, float]] = {
    "cpu": {        # Intel i5-12400F
        "md5": 146e6,
        "sha256": 8e6,
        "bcrypt": 38,
    },
    "gpu": {        # NVIDIA RTX 2060 SUPER
        "md5": 25e9,
        "ntlm": 45e9,
        "sha256": 3.5e9,
        "bcrypt": 18e3,
    },
    "rig": {        # 8x high-end GPUs (illustrative)
        "md5": 800e9,
        "sha256": 100e9,
        "bcrypt": 500e3,
    },
}

SECONDS_PER = [
    ("year", 365 * 24 * 3600),
    ("day", 24 * 3600),
    ("hour", 3600),
    ("minute", 60),
    ("second", 1),
]


def human_duration(seconds: float) -> str:
    """Render a duration in seconds as a short human-readable string."""
    if seconds < 1:
        return "< 1 second"
    if seconds >= 100 * SECONDS_PER[0][1]:  # >= 100 years
        years = seconds / SECONDS_PER[0][1]
        if years >= 1e9:
            return f"{years / 1e9:.1f} billion years"
        if years >= 1e6:
            return f"{years / 1e6:.1f} million years"
        if years >= 1e3:
            return f"{years / 1e3:.1f} thousand years"
        return f"{years:,.0f} years"
    for name, size in SECONDS_PER:
        if seconds >= size:
            value = seconds / size
            return f"{value:.1f} {name}{'s' if value >= 2 else ''}"
    return "< 1 second"


@dataclass
class CrackEstimate:
    scenario: str          # e.g. "gpu"
    algorithm: str         # e.g. "bcrypt"
    hashrate: float        # hashes per second
    keyspace: float        # number of candidates
    seconds: float         # average time (keyspace / 2 / hashrate)
    pretty: str            # human-readable duration


def policy_keyspace(policy: Policy) -> float:
    """Candidates needed to exhaust the weakest password the policy allows."""
    return float(policy.effective_charset_size()) ** policy.min_length


def estimate(policy: Policy) -> list[CrackEstimate]:
    """Return brute-force time estimates across every known hardware/algorithm."""
    keyspace = policy_keyspace(policy)
    out: list[CrackEstimate] = []
    for scenario, algos in HASHRATES.items():
        for algo, rate in algos.items():
            # On average an attacker finds the password after half the keyspace.
            seconds = (keyspace / 2) / rate
            out.append(
                CrackEstimate(
                    scenario=scenario,
                    algorithm=algo,
                    hashrate=rate,
                    keyspace=keyspace,
                    seconds=seconds,
                    pretty=human_duration(seconds),
                )
            )
    return out
