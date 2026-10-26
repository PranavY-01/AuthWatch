"""Strict timestamp profile, integer-microsecond time, and duration parsing.

No function in this module reads the wall clock.
"""

import re
from datetime import datetime, timedelta, timezone, tzinfo

from authwatch.errors import ConfigError

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ONE_US = timedelta(microseconds=1)

# ASCII digits only, uppercase T, mandatory Z or numeric offset; used with fullmatch.
_TS = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})"
)
_OFFSET = re.compile(r"([+-])([0-9]{2}):([0-9]{2})")
_DURATION = re.compile(r"([0-9]{1,12})([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _offset(token: str) -> tzinfo:
    """Turn ``Z`` or ``±HH:MM`` into a fixed-offset timezone; ``-00:00`` is unknown and rejected."""
    if token == "Z":
        return timezone.utc
    m = _OFFSET.fullmatch(token)
    if m is None:
        raise ValueError("offset must be Z or +HH:MM / -HH:MM")
    sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3))
    if hh > 23 or mm > 59:
        raise ValueError("offset out of range")
    if sign == "-" and hh == 0 and mm == 0:
        raise ValueError("offset -00:00 means unknown offset")
    delta = timedelta(hours=hh, minutes=mm)
    return timezone(-delta if sign == "-" else delta)


def parse_ts(s: object) -> datetime:
    """Parse the strict RFC 3339 profile into an aware UTC datetime; raise ValueError otherwise.

    Fractions beyond microseconds are truncated. Error messages never contain the value.
    """
    if not isinstance(s, str):
        raise ValueError("timestamp must be a string")
    m = _TS.fullmatch(s)
    if m is None:
        raise ValueError("timestamp must be RFC 3339 (ASCII) with Z or a known offset")
    year, month, day, hour, minute, second, frac, off = m.groups()
    micro = int((frac or "")[:6].ljust(6, "0"))
    try:
        dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                      micro, tzinfo=_offset(off))
    except ValueError as exc:
        raise ValueError("timestamp is not a valid date, time or offset") from exc
    try:
        return dt.astimezone(timezone.utc)
    except OverflowError as exc:  # e.g. 0001-01-01T00:00:00+05:00 underflows after conversion
        raise ValueError("timestamp out of supported range") from exc


def to_us(dt: datetime) -> int:
    """Aware datetime -> integer microseconds since the Unix epoch (integer arithmetic only)."""
    return (dt - EPOCH) // _ONE_US


def iso_utc(us: int) -> str:
    """Integer microseconds -> ``YYYY-MM-DDTHH:MM:SSZ`` (or ``.ffffffZ`` when sub-second)."""
    dt = EPOCH + timedelta(microseconds=us)
    base = (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
            f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}")
    if dt.microsecond:
        return f"{base}.{dt.microsecond:06d}Z"
    return base + "Z"


def parse_duration(s: object) -> int:
    """Parse ``<integer><s|m|h|d>`` into seconds; anything else is a ConfigError."""
    m = _DURATION.fullmatch(s) if isinstance(s, str) else None
    if m is None:
        raise ConfigError("durations must be an integer followed by s, m, h or d (e.g. 300s, 5m)")
    value = int(m.group(1))
    if value < 1:
        raise ConfigError("durations must be at least 1")
    return value * _UNIT_SECONDS[m.group(2)]


def parse_assumed_tz(s: str) -> tzinfo:
    """Parse ``--assume-tz``: ``Z``, ``UTC`` or a fixed ``±HH:MM`` offset. No IANA names."""
    if s in ("Z", "UTC"):
        return timezone.utc
    try:
        return _offset(s)
    except ValueError:
        raise ConfigError("--assume-tz must be Z, UTC or a fixed offset such as +05:30") from None
