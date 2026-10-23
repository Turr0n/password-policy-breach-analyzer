from ppa.crack_time import estimate, human_duration, policy_keyspace
from ppa.policy import Policy


def test_human_duration_ranges():
    assert human_duration(0.4) == "< 1 second"
    assert "minute" in human_duration(120)
    assert "year" in human_duration(5 * 365 * 24 * 3600)
    assert "million years" in human_duration(2e6 * 365 * 24 * 3600)


def test_keyspace_grows_with_length():
    short = policy_keyspace(Policy(min_length=6, require_lower=True))
    long = policy_keyspace(Policy(min_length=12, require_lower=True))
    assert long > short


def test_estimate_covers_scenarios():
    ests = estimate(Policy(min_length=8, require_lower=True))
    scenarios = {e.scenario for e in ests}
    assert {"cpu", "gpu", "rig"} <= scenarios
    # Slower hash (bcrypt) must take longer than fast hash (md5) on same hardware.
    gpu = {e.algorithm: e.seconds for e in ests if e.scenario == "gpu"}
    assert gpu["bcrypt"] > gpu["md5"]
