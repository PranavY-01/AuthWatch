"""Bytes-level line reader, whole-input checks and hardened JSON parsing (Spec §6.1, errata E3).

Lines are split on ``b"\\n"`` only; every byte read is hashed, including drained over-long
lines, BOMs and blank lines, so the recorded SHA-256 covers the exact file analyzed.
"""

import hashlib
import json
import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from authwatch.errors import InputUnusableError

MAX_LINE = 64 * 1024  # including the terminator
SAMPLE_SIZE = 4096
BOM_UTF8 = b"\xef\xbb\xbf"
_WIDE_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff")  # UTF-16 LE/BE, UTF-32 (LE starts FF FE)

# Stable record-level reason codes; record values are never echoed.
LINE_TOO_LONG = "line_too_long"
NUL_BYTE = "nul_byte"
INVALID_UTF8 = "invalid_utf8"
INVALID_JSON = "invalid_json"
DUPLICATE_KEY = "duplicate_key"
NESTING_TOO_DEEP = "nesting_too_deep"
INVALID_VALUE = "invalid_value"
NOT_AN_OBJECT = "not_an_object"


class DuplicateKeyError(ValueError):
    """A JSON object repeated a key (a later ``outcome`` could otherwise flip a failure)."""


class NonFiniteError(ValueError):
    """NaN, Infinity, or a float literal that overflows to infinity."""


class InputDigest:
    """SHA-256 and byte count of everything read from the input."""

    def __init__(self) -> None:
        self._sha = hashlib.sha256()
        self.size = 0

    def update(self, data: bytes) -> None:
        self._sha.update(data)
        self.size += len(data)

    def hexdigest(self) -> str:
        return self._sha.hexdigest()


@dataclass(frozen=True, slots=True)
class Line:
    """One physical line: raw bytes (terminator and line-1 BOM removed) or a problem code."""

    no: int
    raw: bytes | None
    problem: str | None = None
    blank: bool = False


def check_whole_input(sample: bytes) -> None:
    """Reject UTF-16/32 and binary input as a whole (exit 3) instead of thousands of line errors."""
    if sample.startswith(_WIDE_BOMS):
        raise InputUnusableError(
            "input starts with a UTF-16/UTF-32 byte-order mark; re-save it as UTF-8 "
            "(in PowerShell 5.1 use Out-File -Encoding utf8)")
    if sample and sample.count(0) * 10 >= len(sample):
        raise InputUnusableError(
            "input looks like UTF-16/UTF-32 or binary data (many NUL bytes); re-save it as UTF-8 "
            "(in PowerShell 5.1 use Out-File -Encoding utf8)")


def read_lines(f: BinaryIO, digest: InputDigest) -> Iterator[Line]:
    """Yield every physical line of a binary file. Memory per step stays at MAX_LINE + 1 bytes."""
    no = 0
    while True:
        raw = f.readline(MAX_LINE + 1)
        if not raw:
            return
        digest.update(raw)
        no += 1
        if len(raw) > MAX_LINE:
            while not raw.endswith(b"\n"):  # drain the rest in bounded chunks
                raw = f.readline(MAX_LINE + 1)
                if not raw:
                    break
                digest.update(raw)
            yield Line(no, None, LINE_TOO_LONG)
            continue
        if no == 1 and raw.startswith(BOM_UTF8):
            raw = raw[len(BOM_UTF8):]
        raw = raw.rstrip(b"\r\n")
        if not raw.strip():
            yield Line(no, b"", blank=True)
            continue
        if b"\x00" in raw:
            yield Line(no, None, NUL_BYTE)
            continue
        yield Line(no, raw)


def _reject_dupes(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise DuplicateKeyError("duplicate keys")
    return dict(pairs)


def _reject_constant(_name: str) -> float:
    raise NonFiniteError("non-finite constant")


def _finite_float(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):
        raise NonFiniteError("non-finite float")
    return f


def parse_json_line(raw: bytes) -> object:
    """Strict UTF-8 decode and JSON parse with duplicate-key and non-finite rejection.

    May raise UnicodeDecodeError, DuplicateKeyError, NonFiniteError, json.JSONDecodeError,
    another ValueError (e.g. a huge integer) or RecursionError; map them with problem_for().
    """
    text = raw.decode("utf-8")
    return json.loads(text, object_pairs_hook=_reject_dupes,
                      parse_constant=_reject_constant, parse_float=_finite_float)


def problem_for(exc: BaseException) -> str:
    """Map a parse exception to its stable reason code."""
    if isinstance(exc, UnicodeDecodeError):  # subclass of ValueError: check first
        return INVALID_UTF8
    if isinstance(exc, DuplicateKeyError):
        return DUPLICATE_KEY
    if isinstance(exc, NonFiniteError):
        return INVALID_VALUE
    if isinstance(exc, json.JSONDecodeError):
        return INVALID_JSON
    if isinstance(exc, RecursionError):
        return NESTING_TOO_DEEP
    if isinstance(exc, ValueError):
        return INVALID_VALUE
    raise TypeError("not a parse exception") from exc
