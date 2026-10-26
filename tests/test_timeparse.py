from datetime import timezone

import pytest

from authwatch.errors import ConfigError
from authwatch.timeparse import iso_utc, parse_assumed_tz, parse_duration, parse_ts, to_us

BAD = [
    "2026-10-26T10:00:00",            # naive
    "2026-10-26",                     # date only
    "2026-W44-1",                     # ISO week date
    "20261026T100000Z",               # basic format
    "2026-10-26t10:00:00Z",           # lowercase t
    "2026-10-26T10:00:00z",           # lowercase z
    "2026-10-26T10:00:00Z\n",         # trailing newline
    "２０２６-10-26T10:00:00Z",         # fullwidth digits
    "٢٠٢٦-10-26T10:00:00Z",           # Arabic-Indic digits
    "2026-10-26T10:00:00-00:00",      # unknown offset
    "2026-10-26T24:00:00Z",           # hour 24
    "2026-02-30T10:00:00Z",           # impossible date
    "2026-10-26T10:00:00+99:99",      # offset out of range
    "2026-10-26T10:00:00+24:00",
    "2026-12-31T23:59:60Z",           # leap second
    "2026-10-26T10:00:00.1234567890Z",  # 10 fraction digits
    "2026-10-26 10:00:00Z",           # space separator
    " 2026-10-26T10:00:00Z",
]


@pytest.mark.parametrize("value", BAD)
def test_rejected_forms(value):
    """Case 27: naive, date-only, week, lowercase, trailing newline, non-ASCII digits, -00:00,
    hour 24, Feb 30, +99:99 and leap seconds are all invalid."""
    with pytest.raises(ValueError):
        parse_ts(value)


def test_non_string_rejected():
    with pytest.raises(ValueError):
        parse_ts(1729936800)


def test_overflow_after_conversion_is_value_error():
    """Case 28: 0001-01-01T00:00:00+05:00 underflows after UTC conversion -> ValueError."""
    with pytest.raises(ValueError):
        parse_ts("0001-01-01T00:00:00+05:00")
    with pytest.raises(ValueError):
        parse_ts("9999-12-31T23:59:59-05:00")


def test_nanoseconds_truncated():
    """Case 29: a 9-digit fraction is truncated (not rounded) to microseconds."""
    dt = parse_ts("2026-10-26T10:00:00.123456789Z")
    assert dt.microsecond == 123456
    assert parse_ts("2026-10-26T10:00:00.999999999Z").second == 0


def test_mixed_offsets_compare_as_utc():
    """Case 35: the same instant written with different offsets yields the same integer."""
    a = to_us(parse_ts("2026-10-26T10:30:00+05:30"))
    b = to_us(parse_ts("2026-10-26T05:00:00Z"))
    c = to_us(parse_ts("2026-10-25T23:00:00-06:00"))
    assert a == b == c
    # String order disagrees with instant order across offsets; integers do not.
    assert "2026-10-26T10:30:00+05:30" > "2026-10-26T05:30:00Z"
    assert a < to_us(parse_ts("2026-10-26T05:30:00Z"))


def test_parse_ts_returns_aware_utc():
    dt = parse_ts("2026-10-26T10:00:00+05:30")
    assert dt.tzinfo == timezone.utc and dt.hour == 4 and dt.minute == 30


def test_to_us_exact_and_iso_round_trip():
    assert to_us(parse_ts("1970-01-01T00:00:00Z")) == 0
    assert to_us(parse_ts("1970-01-01T00:00:01.000001Z")) == 1_000_001
    for s in ["2026-10-26T10:00:00Z", "2026-10-26T10:00:00.000001Z", "2999-01-01T00:00:00Z",
              "1969-12-31T23:59:59.5Z"]:
        us = to_us(parse_ts(s))
        out = iso_utc(us)
        assert to_us(parse_ts(out)) == us
    assert iso_utc(500_000) == "1970-01-01T00:00:00.500000Z"
    assert iso_utc(0) == "1970-01-01T00:00:00Z"


@pytest.mark.parametrize("text,seconds", [("300s", 300), ("5m", 300), ("1h", 3600), ("2d", 172800),
                                          ("1s", 1)])
def test_duration_grammar(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["300", "5 m", "5M", "0s", "-5s", "1.5h", "", "1w", "s",
                                  "３００s", "5m ", "1" * 13 + "s"])
def test_duration_rejects(text):
    with pytest.raises(ConfigError):
        parse_duration(text)


def test_assumed_tz():
    assert parse_assumed_tz("Z") == timezone.utc
    assert parse_assumed_tz("UTC") == timezone.utc
    assert parse_assumed_tz("+05:30").utcoffset(None).total_seconds() == 19800
    for bad in ["-00:00", "+24:00", "+05:60", "Europe/London", "utc", "+0530", ""]:
        with pytest.raises(ConfigError):
            parse_assumed_tz(bad)
