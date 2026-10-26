import sys
import unicodedata

import pytest

from authwatch.keys import ip_key, username_key


def test_username_variants_merge():
    """Case 31: Alice, fullwidth ａｌｉｃｅ and alice+ZWSP share one key; the invisible one is flagged."""
    assert username_key("Alice") == ("alice", False)
    assert username_key("ａｌｉｃｅ") == ("alice", False)
    assert username_key("alice​") == ("alice", True)
    assert username_key("ALICE") == ("alice", False)


def test_zero_width_only_username_has_no_key():
    """Case 32: a username of only zero-width characters has no key (missing_username)."""
    assert username_key("​‌⁠") == (None, True)
    assert username_key("") == (None, False)


def test_control_characters_flagged_but_kept():
    key, suspicious = username_key("admin\x1b[2J")
    assert suspicious and key == "admin\x1b[2j"


def test_username_key_idempotent_over_all_code_points():
    """Every single code point: applying username_key to a key changes nothing.
    (The first version of the function failed for 26 code points.)"""
    failures = []
    for cp in range(sys.maxunicode + 1):
        if 0xD800 <= cp <= 0xDFFF:
            continue
        key, _ = username_key(chr(cp))
        if key is None:
            continue
        again, _ = username_key(key)
        if again != key or unicodedata.normalize("NFKC", key) != key:
            failures.append(cp)
    assert failures == []


def test_ipv4_mapped_forms_merge():
    """Case 33: ::ffff:1.2.3.4, ::FFFF:1.2.3.4 and 1.2.3.4 share the key 1.2.3.4."""
    assert ip_key("::ffff:1.2.3.4")[0] == "1.2.3.4"
    assert ip_key("::FFFF:1.2.3.4")[0] == "1.2.3.4"
    assert ip_key("1.2.3.4")[0] == "1.2.3.4"


def test_ip_scope_forms():
    """Case 24: 1.2.3.4%eth0 is invalid; fe80::1%eth0 is accepted with the scope stripped."""
    with pytest.raises(ValueError):
        ip_key("1.2.3.4%eth0")
    with pytest.raises(ValueError):
        ip_key("fe80::1%")
    assert ip_key("fe80::1%eth0") == ("fe80::1", "eth0")


def test_ipv6_canonical_text():
    assert ip_key("2001:DB8:0:0:0:0:0:1") == ("2001:db8::1", None)


@pytest.mark.parametrize("bad", [3232235801, True, None, b"1.2.3.4", "", " 1.2.3.4", "1.2.3.4 ",
                                 "192.168.001.025", "-", "١.٢.٣.٤", "1.2.3.4.5", "x" * 10000,
                                 "203.0.113.999"])
def test_ip_rejects(bad):
    with pytest.raises(ValueError):
        ip_key(bad)
