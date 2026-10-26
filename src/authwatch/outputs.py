"""Input checks, output-path safety and atomic writes (Spec §9.4, errata E1)."""

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from authwatch.errors import ConfigError, OperationalError

PROBE_LIMIT = 16 * 1024 * 1024


def same_file(a: Path, b: Path) -> bool:
    """Resolved-path equality or ``os.path.samefile`` (which also catches hard links)."""
    try:
        if Path(a).resolve() == Path(b).resolve():
            return True
    except OSError:
        pass
    try:
        return os.path.samefile(a, b)
    except OSError:  # includes FileNotFoundError: a path that does not exist is not the input
        return False


def check_input(path: Path) -> None:
    """The input must exist and be a regular file (exit 2 otherwise)."""
    try:
        if not path.exists():
            raise ConfigError(f"input file not found: {path}")
        if path.is_dir():
            raise ConfigError(f"input is a directory: {path}")
        if not path.is_file():
            raise ConfigError(f"input is not a regular file: {path}")
    except OSError as exc:
        raise OperationalError(f"cannot inspect input: {path}") from exc


def _is_authwatch_report(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            data = f.read(PROBE_LIMIT + 1)
    except OSError:
        return False
    if len(data) > PROBE_LIMIT:
        return False
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        return False
    envelope = obj.get("envelope") if isinstance(obj, dict) else None
    return isinstance(envelope, dict) and envelope.get("tool") == "AuthWatch"


def check_output_path(path: Path, input_path: Path, others: Iterable[Path], *,
                      probe_report: bool, force: bool) -> None:
    """Refuse (exit 2) anything that could destroy evidence or a foreign file.

    An existing file is overwritten only if it is an AuthWatch report (``probe_report``) or
    ``--force-report`` is given. Directories, symlinks, the input itself (including hard
    links to it) and the other output paths are always refused.
    """
    label = str(path)
    parent = path.parent
    if not parent.is_dir():
        raise ConfigError(f"output directory does not exist: {label}")
    if path.is_symlink():
        raise ConfigError(f"refusing to write to a symlink: {label}")
    if path.is_dir():
        raise ConfigError(f"output path is a directory: {label}")
    if same_file(path, input_path):
        raise ConfigError(f"refusing to write over the input file: {label}")
    for other in others:
        if same_file(path, other):
            raise ConfigError(f"output paths must differ: {label}")
    if path.exists() and not force:
        if probe_report and _is_authwatch_report(path):
            return
        raise ConfigError(f"refusing to overwrite an existing file that is not an AuthWatch "
                          f"report: {label} (use --force-report)")


def write_atomic(path: Path, data: bytes) -> None:
    """Temp file in the same directory -> fsync -> os.replace. The original survives failure.

    ``mkstemp`` creates the file with mode 0600 on POSIX.
    """
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".authwatch-tmp-")
    except OSError as exc:
        raise OperationalError(f"cannot write output: {path}") from exc
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        Path(tmp).unlink(missing_ok=True)
        raise OperationalError(f"cannot write output: {path}") from exc
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
