"""Strict event schema 1.0 and validation reason codes."""

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, ValidationInfo, field_validator

from authwatch.keys import ip_key
from authwatch.timeparse import parse_ts

# Adapter classifications: every non-blank record is exactly one of these.
EVENT = "event"
IRRELEVANT = "irrelevant"
UNSUPPORTED = "unsupported"
INVALID = "invalid"

INVALID_TIMESTAMP = "invalid_timestamp"
_TOKEN = r"^[a-z0-9][a-z0-9._-]*$"
_FIELD_LIST_MAX = 40


def _check_text(v: Optional[str]) -> Optional[str]:
    if v is not None:
        v.encode("utf-8")  # lone surrogate -> error here, not at export time
        if "\x00" in v:
            raise ValueError("NUL character")
    return v


class AuthEvent(BaseModel):
    """One authentication record. ``timestamp``, ``username`` and ``source_ip`` are required
    keys that may hold null; a missing key is an error."""

    model_config = ConfigDict(strict=True, extra="forbid")

    schema_version: Literal["1.0"]
    event_type: Literal["authentication"]
    timestamp: Optional[str]
    outcome: Literal["success", "failure", "unknown"]
    username: Optional[str] = Field(max_length=256)
    source_ip: Optional[str]
    source_os: str = Field(pattern=_TOKEN, max_length=32)
    source_product: str = Field(pattern=_TOKEN, max_length=64)
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    event_id: Optional[str] = Field(default=None, max_length=64)
    record_id: Optional[str] = Field(default=None, max_length=128)
    source_host: Optional[str] = Field(default=None, max_length=255)
    failure_reason: Optional[Literal["bad_credential", "unknown_account", "locked",
                                     "disabled", "expired", "other"]] = None
    auth_method: Optional[str] = Field(default=None, max_length=32)
    logon_type: Optional[int] = Field(default=None, ge=0, le=255)
    parser_name: Optional[str] = Field(default=None, max_length=64)
    parse_warnings: list[Annotated[str, Field(max_length=200)]] = Field(
        default_factory=list, max_length=16)

    @field_validator("username", "event_id", "record_id", "source_host", "auth_method",
                     "parser_name")
    @classmethod
    def _text(cls, v: Optional[str]) -> Optional[str]:
        return _check_text(v)

    @field_validator("parse_warnings")
    @classmethod
    def _warnings_text(cls, v: list[str]) -> list[str]:
        for item in v:
            _check_text(item)
        return v

    @field_validator("timestamp")
    @classmethod
    def _timestamp(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            parse_ts(v)
        return v

    @field_validator("source_ip")
    @classmethod
    def _source_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            _check_text(v)
            ip_key(v)
        return v

    @field_validator("failure_reason")
    @classmethod
    def _failure_reason(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        outcome = info.data.get("outcome")
        if v is not None and outcome is not None and outcome != "failure":
            raise ValueError("failure_reason requires outcome failure")
        return v


def reason_for(exc: ValidationError) -> str:
    """Stable reason code for a failed validation. Lists field names only; an unknown field
    contributes ``unknown_field`` because its name is attacker-controlled."""
    names: set[str] = set()
    types: set[str] = set()
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        if err["type"] == "extra_forbidden":
            names.add("unknown_field")
            continue
        loc = err.get("loc") or ()
        names.add(str(loc[0]) if loc else "record")
        types.add(err["type"])
    if names == {"timestamp"} and types == {"value_error"}:
        return INVALID_TIMESTAMP
    return "schema_invalid:" + ",".join(sorted(names))[:_FIELD_LIST_MAX]
