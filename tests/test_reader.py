import hashlib
import io
import json

import pytest

from authwatch.adapters.jsonl import JsonlAdapter
from authwatch.errors import InputUnusableError
from authwatch.models import EVENT, INVALID
from authwatch.reader import (MAX_LINE, InputDigest, check_whole_input, parse_json_line,
                              problem_for, read_lines)
from conftest import record

ADAPTER = JsonlAdapter()


def lines_of(data: bytes):
    digest = InputDigest()
    out = list(read_lines(io.BytesIO(data), digest))
    return out, digest


def classify(data: bytes):
    """Return a list of (line number, 'blank' | 'event' | reason code)."""
    out, _ = lines_of(data)
    result = []
    for ln in out:
        if ln.blank:
            result.append((ln.no, "blank"))
        elif ln.problem:
            result.append((ln.no, ln.problem))
        else:
            _, cls, reason = ADAPTER.adapt(ln)
            result.append((ln.no, "event" if cls == EVENT else reason))
    return result


GOOD = json.dumps(record()).encode()


def test_empty_and_blank_only():
    """Case 1: an empty file has no lines; whitespace-only lines are blank, not records."""
    assert classify(b"") == []
    assert classify(b"\n  \n\t\r\n") == [(1, "blank"), (2, "blank"), (3, "blank")]


def test_bom_first_line_accepted_later_rejected():
    """Case 2: a UTF-8 BOM on line 1 is removed; on a later line the record is invalid_json."""
    data = b"\xef\xbb\xbf" + GOOD + b"\n\xef\xbb\xbf" + GOOD + b"\n"
    assert classify(data) == [(1, "event"), (2, "invalid_json")]


def test_crlf_and_missing_final_newline():
    """Case 3: CRLF endings and a last line without a newline are accepted."""
    assert classify(GOOD + b"\r\n" + GOOD) == [(1, "event"), (2, "event")]


def test_lone_cr_is_one_invalid_line():
    """Case 4: lone CR separators are not line breaks; the file is one invalid line."""
    assert classify(GOOD + b"\r" + GOOD + b"\r" + GOOD) == [(1, "invalid_json")]


def test_u2028_inside_string_is_one_record():
    """Case 5: U+2028 / U+2029 inside a string do not split the record."""
    data = json.dumps(record(username="a b c"), ensure_ascii=False).encode("utf-8")
    assert classify(data + b"\n") == [(1, "event")]


@pytest.mark.parametrize("data", [
    "\ufeff{}\n".encode("utf-16-le"),
    "{}\n".encode("utf-16"),              # with BOM
    "{}\n".encode("utf-16-be"),           # no BOM, NUL-heavy
    ("{" + '"a":1,' * 200 + "}\n").encode("utf-16-le"),  # no BOM
    "{}\n".encode("utf-32"),
    b"\x7fELF\x02\x01\x01" + b"\x00" * 600 + bytes(range(256)) * 8,  # NUL-heavy binary
], ids=["utf16le-bom", "utf16-bom", "utf16be-nobom", "utf16le-nobom", "utf32", "binary"])
def test_wide_or_binary_input_rejected_as_whole(data):
    """Case 6: UTF-16 with or without BOM, UTF-32 and binary data are whole-input failures."""
    with pytest.raises(InputUnusableError) as info:
        check_whole_input(data[:4096])
    assert "UTF-8" in str(info.value)


def test_isolated_nul_is_per_line():
    """Case 7: one isolated NUL byte invalidates only its line and does not trigger exit 3."""
    data = GOOD + b"\n" + GOOD[:10] + b"\x00" + GOOD[10:] + b"\n" + GOOD + b"\n"
    check_whole_input(data[:4096])
    assert classify(data) == [(1, "event"), (2, "nul_byte"), (3, "event")]


def test_empty_input_is_not_utf16():
    check_whole_input(b"")


class TrackingIO(io.BytesIO):
    """Records the largest chunk a single readline() returned."""

    peak = 0

    def readline(self, size=-1):
        chunk = super().readline(size)
        self.peak = max(self.peak, len(chunk))
        return chunk


def test_long_lines_bounded_and_next_line_read():
    """Case 8: a line over 64 KiB (and a 10 MB line) is line_too_long, memory per read stays at
    64 KiB + 1, and the following line is read correctly."""
    exact = b"x" * (MAX_LINE - 1) + b"\n"            # exactly 64 KiB including terminator
    over = b"x" * MAX_LINE + b"\n"                    # 64 KiB + 1 including terminator
    huge = b"y" * (10 * 1024 * 1024) + b"\n"
    data = exact + over + huge + GOOD + b"\n" + b"z" * (MAX_LINE + 1)
    f = TrackingIO(data)
    digest = InputDigest()
    out = list(read_lines(f, digest))
    assert [(ln.no, ln.problem) for ln in out] == [
        (1, None), (2, "line_too_long"), (3, "line_too_long"), (4, None), (5, "line_too_long")]
    assert out[3].raw == GOOD
    assert f.peak <= MAX_LINE + 1


def test_hash_covers_every_byte_including_drained():
    """The digest equals SHA-256 of the whole file, including BOM, blank and drained bytes."""
    data = b"\xef\xbb\xbf" + GOOD + b"\n\n" + b"q" * (3 * MAX_LINE) + b"\n" + GOOD
    out, digest = lines_of(data)
    assert digest.hexdigest() == hashlib.sha256(data).hexdigest()
    assert digest.size == len(data)


def test_invalid_utf8():
    """Case 9: invalid UTF-8 bytes -> invalid_utf8."""
    bad = GOOD.replace(b'"alice"', b'"al\xffice"')
    assert classify(bad + b"\n") == [(1, "invalid_utf8")]


@pytest.mark.parametrize("raw", [b'{"a":', b"{", b'{"outcome":"failure"', b"not json", b"{'a':1}",
                                 b'{"a":1}{"b":2}', b'{"a":1,}'])
def test_malformed_json(raw):
    """Case 10: malformed or truncated JSON -> invalid_json."""
    assert classify(raw + b"\n") == [(1, "invalid_json")]


@pytest.mark.parametrize("raw", [
    b'{"outcome":"failure","outcome":"success"}',
    b'{"a":{"b":1,"b":2}}',
    b'{"a":1,"\\u0061":2}',
])
def test_duplicate_keys(raw):
    """Case 11: duplicate keys at top level, nested, or equal after escape decoding."""
    assert classify(raw + b"\n") == [(1, "duplicate_key")]


@pytest.mark.parametrize("raw", [b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
                                 b'{"a":1e999}', b'{"a":-1e999}'])
def test_non_finite(raw):
    """Case 12: NaN, Infinity and 1e999 -> invalid_value."""
    assert classify(raw + b"\n") == [(1, "invalid_value")]


def test_huge_integer():
    """Case 13: a 5 000-digit integer is a ValueError (not JSONDecodeError) -> invalid_value."""
    assert classify(b'{"a":' + b"7" * 5000 + b"}\n") == [(1, "invalid_value")]


def test_deep_nesting():
    """Case 14: 30 000-deep nesting -> nesting_too_deep (RecursionError caught)."""
    assert classify(b"[" * 30000 + b"]" * 30000 + b"\n") == [(1, "nesting_too_deep")]
    assert classify(b'{"a":' * 9000 + b"1" + b"}" * 9000 + b"\n") == [(1, "nesting_too_deep")]


@pytest.mark.parametrize("raw", [b"[1,2]", b"42", b'"x"', b"null", b"true"])
def test_not_an_object(raw):
    """Case 15: a top-level array or scalar -> not_an_object."""
    assert classify(raw + b"\n") == [(1, "not_an_object")]


def test_problem_for_rejects_unrelated_exceptions():
    with pytest.raises(TypeError):
        problem_for(KeyError("x"))


def test_parse_json_line_returns_object():
    assert parse_json_line(b'{"a":[1,2.5]}') == {"a": [1, 2.5]}
