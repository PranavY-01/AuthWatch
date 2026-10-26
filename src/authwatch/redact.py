"""Keyed username redaction for every output (Spec §6.11, decision D8).

Grouping happens on the real username key before display, so redaction never changes
which alerts fire; it changes only what is shown.
"""

import hashlib
import hmac
import secrets
from collections.abc import Mapping

from authwatch.errors import ConfigError

ENV_KEY = "AUTHWATCH_REDACT_KEY"
MIN_KEY_BYTES = 32
ALGORITHM = "hmac-sha256/12"
NO_KEY = "<none>"


class Redactor:
    """``u:`` + first 12 hex of HMAC-SHA256(key, username_key). No key -> random per run."""

    def __init__(self, key: bytes | None = None) -> None:
        if key is None:
            self._key = secrets.token_bytes(MIN_KEY_BYTES)
            self.key_source = "ephemeral"
        else:
            if len(key) < MIN_KEY_BYTES:
                raise ConfigError(f"{ENV_KEY} must be at least {MIN_KEY_BYTES} bytes")
            self._key = key
            self.key_source = "env"

    def token(self, username_key: str) -> str:
        digest = hmac.new(self._key, username_key.encode("utf-8"), hashlib.sha256).hexdigest()
        return "u:" + digest[:12]

    def display(self, username_key: str | None) -> str:
        return NO_KEY if username_key is None else self.token(username_key)

    def describe(self) -> dict:
        return {"enabled": True, "algorithm": ALGORITHM, "key_source": self.key_source}


class NoRedaction:
    """Identity display used when redaction is not requested."""

    key_source = None

    def display(self, username_key: str | None) -> str:
        return NO_KEY if username_key is None else username_key

    def describe(self) -> None:
        return None


def from_environment(environ: Mapping[str, str]) -> Redactor:
    """Key from AUTHWATCH_REDACT_KEY (UTF-8 bytes) when set, else an ephemeral key."""
    value = environ.get(ENV_KEY)
    return Redactor(None if value is None else value.encode("utf-8"))
