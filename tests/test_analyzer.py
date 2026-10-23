from ppa.analyzer import analyze
from ppa.policy import Policy

CORPUS = [
    "123456",          # 6, digits only
    "password",        # 8, lower only
    "iloveyou",        # 8, lower only
    "Password1",       # 9, upper+lower+digit
    "Tr0ub4dour&3",    # 12, all classes
    "qwerty",          # 6, lower only
]


def test_counts_add_up():
    p = Policy(min_length=8)
    r = analyze(p, CORPUS)
    assert r.total == 6
    assert r.compliant + r.rejected == r.total


def test_compliant_rate():
    # min_length 8 keeps the four 8+ char entries.
    p = Policy(min_length=8)
    r = analyze(p, CORPUS)
    assert r.compliant == 4
    assert r.rejected == 2
    assert abs(r.compliant_rate - 4 / 6) < 1e-9


def test_strict_policy_blocks_most():
    p = Policy(min_length=10, require_upper=True, require_digit=True, require_symbol=True)
    r = analyze(p, CORPUS)
    # Only "Tr0ub4dour&3" survives.
    assert r.compliant == 1
    assert r.sample_compliant == ["Tr0ub4dour&3"]


def test_limit():
    p = Policy(min_length=1)
    r = analyze(p, CORPUS, limit=2)
    assert r.total == 2


def test_failure_reasons_recorded():
    p = Policy(min_length=8)
    r = analyze(p, CORPUS)
    assert sum(r.failure_reasons.values()) >= 2
