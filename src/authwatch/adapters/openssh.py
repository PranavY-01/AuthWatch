"""OpenSSH text adapter (Spec §6.10.3, decision D11). EXPERIMENTAL.

Status: PROPOSED. Validated only against authored samples, not real sshd logs.

Every line is exactly one of: event (a supported ``Failed ...`` / ``Accepted ...``
message), irrelevant (another process, or listed sshd bookkeeping), unsupported (unknown
shape, unknown sshd message, or a repeat summary) or invalid (no buildable timestamp).

Attacker-controlled fields are sanitized with a warning; a recognised authentication line
is never rejected because of its username, address or port (Spec §6.10.1).
"""

import re
from datetime import datetime, timezone, tzinfo

from pydantic import ValidationError

from authwatch.errors import ConfigError
from authwatch.keys import ip_key
from authwatch.models import EVENT, INVALID, INVALID_TIMESTAMP, IRRELEVANT, UNSUPPORTED, \
    AuthEvent, reason_for
from authwatch.reader import Line
from authwatch.timeparse import iso_utc, parse_ts, to_us

SYSLOG = re.compile(r"(?P<mon>[A-Z][a-z]{2}) +(?P<day>[0-9]{1,2}) "
                    r"(?P<hms>[0-9]{2}:[0-9]{2}:[0-9]{2}) (?P<host>\S+) "
                    r"(?P<proc>[^\s:\[\]]+)(?:\[[0-9]+\])?: (?P<msg>.*)")
RFC3339 = re.compile(r"(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}T\S+) (?P<host>\S+) "
                     r"(?P<proc>[^\s:\[\]]+)(?:\[[0-9]+\])?: (?P<msg>.*)")
FP = r"(?:: [A-Z0-9-]+ (?:SHA256|MD5):\S+)?"   # explicit key-fingerprint suffix, no free text
# Greedy user + end anchor: the last well-formed "from <ip> port <n> ssh2" tail wins, so a
# username cannot spoof the source address. Port is \S+ so a bad port is sanitized, not
# a reason to drop the line.
FAILED = re.compile(r"Failed (?P<method>[a-z][a-z-]*(?:/[a-z]+)?) for (?P<inv>invalid user )?"
                    r"(?P<user>.*) from (?P<ip>\S+) port (?P<port>\S+) ssh2" + FP)
ACCEPTED = re.compile(r"Accepted (?P<method>[a-z][a-z-]*(?:/[a-z]+)?) for (?P<user>.*) "
                      r"from (?P<ip>\S+) port (?P<port>\S+) ssh2" + FP)
REPEAT = re.compile(r"(?:last )?message repeated [0-9]+ times?.*")
PORT = re.compile(r"[0-9]{1,5}")
REGEXES = {"syslog": SYSLOG, "rfc3339": RFC3339, "failed": FAILED, "accepted": ACCEPTED,
           "repeat": REPEAT}

IRRELEVANT_PREFIXES = (
    "Invalid user ", "Connection closed by", "Connection reset by", "Disconnected from",
    "Received disconnect from", "Disconnecting", "Server listening on", "Received signal",
    "Starting session", "pam_unix(sshd:auth): authentication failure", "pam_unix(sshd:session):",
)
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                                      "Sep", "Oct", "Nov", "Dec"), 1)}

UNSUPPORTED_SHAPE = "unsupported_line_shape"
UNSUPPORTED_SSHD = "unsupported_sshd_message"
REPEAT_SUMMARY = "repeat_summary"

W_UTF8 = "invalid_utf8_replaced"
W_USER_TRUNCATED = "username_truncated"
W_IP = "source_ip_unparseable"
W_PORT = "source_port_out_of_range"
MAX_USERNAME = 256


def classify(msg: str) -> str:
    """Classify an sshd message body (no header): failed | accepted | repeat | irrelevant |
    unsupported."""
    if FAILED.fullmatch(msg):
        return "failed"
    if ACCEPTED.fullmatch(msg):
        return "accepted"
    if REPEAT.fullmatch(msg):
        return "repeat"
    if msg.startswith(IRRELEVANT_PREFIXES):
        return "irrelevant"
    return "unsupported"


class OpenSSHAdapter:
    """Stateful per input: tracks the classic-syslog month to roll the assumed year over."""

    name = "openssh"

    def __init__(self, assume_year: int | None = None, assume_tz: tzinfo | None = None) -> None:
        self.assume_year = assume_year
        self.assume_tz = assume_tz
        self._year_offset = 0
        self._prev_month: int | None = None

    def _syslog_time(self, m: re.Match) -> str | None:
        if self.assume_year is None or self.assume_tz is None:
            raise ConfigError("classic syslog timestamps have no year or timezone; pass "
                              "--assume-year and --assume-tz")
        month = MONTHS.get(m["mon"])
        if month is None:
            return None
        if self._prev_month == 12 and month == 1:
            self._year_offset += 1
        self._prev_month = month
        hh, mm, ss = (int(x) for x in m["hms"].split(":"))
        try:
            local = datetime(self.assume_year + self._year_offset, month, int(m["day"]), hh, mm,
                             ss, tzinfo=self.assume_tz)
            return iso_utc(to_us(local.astimezone(timezone.utc)))
        except (ValueError, OverflowError):
            return None

    def adapt(self, line: Line) -> tuple[AuthEvent | None, str, str | None]:
        warnings: list[str] = []
        try:
            text = line.raw.decode("utf-8")
        except UnicodeDecodeError:
            text = line.raw.decode("utf-8", errors="replace")
            warnings.append(W_UTF8)
        m = SYSLOG.fullmatch(text)
        if m is not None:
            timestamp = self._syslog_time(m)
        else:
            m = RFC3339.fullmatch(text)
            if m is None:
                return None, UNSUPPORTED, UNSUPPORTED_SHAPE
            timestamp = m["ts"]
            try:
                parse_ts(timestamp)
            except ValueError:
                timestamp = None
        if timestamp is None:
            return None, INVALID, INVALID_TIMESTAMP
        if not m["proc"].startswith("sshd"):
            return None, IRRELEVANT, None
        msg = m["msg"]
        kind = classify(msg)
        if kind == "repeat":
            return None, UNSUPPORTED, REPEAT_SUMMARY
        if kind == "irrelevant":
            return None, IRRELEVANT, None
        if kind == "unsupported":
            return None, UNSUPPORTED, UNSUPPORTED_SSHD
        mm = (FAILED if kind == "failed" else ACCEPTED).fullmatch(msg)
        return self._event(mm, kind, timestamp, m["host"], warnings)

    def _event(self, mm: re.Match, kind: str, timestamp: str, host: str,
               warnings: list[str]) -> tuple[AuthEvent | None, str, str | None]:
        user = mm["user"]
        if len(user) > MAX_USERNAME:
            user = user[:MAX_USERNAME]
            warnings.append(W_USER_TRUNCATED)
        ip: str | None = mm["ip"]
        try:
            ip_key(ip)
        except ValueError:
            ip = None
            warnings.append(W_IP)
        port: int | None = None
        if PORT.fullmatch(mm["port"]) and int(mm["port"]) <= 65535:
            port = int(mm["port"])
        else:
            warnings.append(W_PORT)
        method = mm["method"]
        failure_reason = None
        if kind == "failed":
            if mm["inv"]:
                failure_reason = "unknown_account"
            elif method == "password" or method.startswith("keyboard-interactive"):
                failure_reason = "bad_credential"
        record = {
            "schema_version": "1.0", "event_type": "authentication", "timestamp": timestamp,
            "outcome": "failure" if kind == "failed" else "success", "username": user,
            "source_ip": ip, "source_os": "linux", "source_product": "openssh",
            "source_port": port, "event_id": None, "record_id": None, "source_host": host,
            "failure_reason": failure_reason, "auth_method": method.split("/")[0],
            "logon_type": None, "parser_name": "openssh-v1", "parse_warnings": warnings,
        }
        try:
            return AuthEvent.model_validate(record), EVENT, None
        except ValidationError as exc:  # structural only, e.g. a 300-character host name
            return None, INVALID, reason_for(exc)
