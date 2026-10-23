from ppa.policy import Policy, char_classes


def test_char_classes_detects_all():
    assert char_classes("aB3!") == {"lower", "upper", "digit", "symbol"}
    assert char_classes("abc") == {"lower"}


def test_min_length():
    p = Policy(min_length=8)
    assert not p.passes("short")
    assert p.passes("longenough")


def test_required_classes():
    p = Policy(min_length=4, require_upper=True, require_digit=True)
    ok, reasons = p.evaluate("abcd")
    assert not ok
    assert any("uppercase" in r for r in reasons)
    assert any("digit" in r for r in reasons)
    assert p.passes("Abc1")


def test_min_char_classes():
    p = Policy(min_length=4, min_char_classes=3)
    assert not p.passes("abcd")      # 1 class
    assert p.passes("aB3x")          # 3 classes


def test_max_length():
    p = Policy(min_length=1, max_length=5)
    assert not p.passes("toolongpassword")
    assert p.passes("okay")


def test_effective_charset_size():
    assert Policy().effective_charset_size() == 26  # nothing required -> lower
    p = Policy(require_lower=True, require_digit=True)
    assert p.effective_charset_size() == 36
    full = Policy(require_lower=True, require_upper=True, require_digit=True, require_symbol=True)
    assert full.effective_charset_size() == 26 + 26 + 10 + 32


def test_roundtrip_dict():
    p = Policy(min_length=12, require_symbol=True)
    assert Policy.from_dict(p.to_dict()) == p
