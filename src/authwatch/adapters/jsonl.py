"""JSONL adapter: normalized schema-1.0 events, one per line.

This is the strict contract: every non-blank line must validate. There is no
"unsupported" or "irrelevant" class for JSONL.
"""

from pydantic import ValidationError

from authwatch.models import EVENT, INVALID, AuthEvent, reason_for
from authwatch.reader import NOT_AN_OBJECT, Line, parse_json_line, problem_for


class JsonlAdapter:
    """Turns a reader Line into ``(AuthEvent | None, classification, reason | None)``."""

    name = "jsonl"

    def adapt(self, line: Line) -> tuple[AuthEvent | None, str, str | None]:
        try:
            obj = parse_json_line(line.raw)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            return None, INVALID, problem_for(exc)
        if not isinstance(obj, dict):
            return None, INVALID, NOT_AN_OBJECT
        try:
            event = AuthEvent.model_validate(obj)
        except ValidationError as exc:
            return None, INVALID, reason_for(exc)
        return event, EVENT, None


_DEFAULT = JsonlAdapter()


def adapt(line: Line) -> tuple[AuthEvent | None, str, str | None]:
    return _DEFAULT.adapt(line)
