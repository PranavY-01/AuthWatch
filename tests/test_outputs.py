import json
import os

import pytest

from authwatch import outputs
from authwatch.errors import ConfigError, OperationalError
from authwatch.outputs import check_input, check_output_path, same_file, write_atomic
from conftest import IS_WINDOWS, needs_symlink


@pytest.fixture
def inp(tmp_path):
    p = tmp_path / "in.jsonl"
    p.write_bytes(b"{}\n")
    return p


def check(path, inp, others=(), probe=True, force=False):
    check_output_path(path, inp, list(others), probe_report=probe, force=force)


def test_report_equal_to_input_refused(inp, tmp_path):
    """Case 55: --report equal to the input (same path, relative spelling, hard link) -> exit 2."""
    with pytest.raises(ConfigError):
        check(inp, inp)
    with pytest.raises(ConfigError):
        check(tmp_path / "." / "in.jsonl", inp, force=True)
    link = tmp_path / "hard.jsonl"
    os.link(inp, link)
    assert same_file(link, inp)
    with pytest.raises(ConfigError):
        check(link, inp, force=True)
    assert inp.read_bytes() == b"{}\n"


@needs_symlink
def test_symlink_to_input_refused(inp, tmp_path):
    """Case 55: a symlink pointing at the input is refused."""
    link = tmp_path / "sym.jsonl"
    os.symlink(inp, link)
    with pytest.raises(ConfigError):
        check(link, inp, force=True)


def test_directory_or_missing_parent_refused(inp, tmp_path):
    """Case 56: a report path that is a directory, or whose parent is missing, is refused."""
    (tmp_path / "d").mkdir()
    with pytest.raises(ConfigError):
        check(tmp_path / "d", inp, force=True)
    with pytest.raises(ConfigError):
        check(tmp_path / "missing" / "r.json", inp)


@needs_symlink
def test_symlink_report_path_refused(inp, tmp_path):
    """Case 56: a report path that is a symlink (even to a harmless file) is refused."""
    target = tmp_path / "t.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "r.json"
    os.symlink(target, link)
    with pytest.raises(ConfigError):
        check(link, inp, force=True)


def test_foreign_file_refused_unless_forced(inp, tmp_path):
    """Case 57: an existing non-AuthWatch file is refused unless --force-report."""
    foreign = tmp_path / "notes.json"
    foreign.write_text('{"envelope": {"tool": "FileSift"}}', encoding="utf-8")
    with pytest.raises(ConfigError):
        check(foreign, inp)
    check(foreign, inp, force=True)
    garbage = tmp_path / "g.json"
    garbage.write_bytes(b"\xff\x00 not json")
    with pytest.raises(ConfigError):
        check(garbage, inp)
    ours = tmp_path / "ours.json"
    ours.write_text(json.dumps({"envelope": {"tool": "AuthWatch"}}), encoding="utf-8")
    check(ours, inp)
    with pytest.raises(ConfigError):   # CSV / normalize outputs are never probed
        check(ours, inp, probe=False)


def test_oversized_existing_report_refused(inp, tmp_path, monkeypatch):
    monkeypatch.setattr(outputs, "PROBE_LIMIT", 10)
    big = tmp_path / "big.json"
    big.write_text(json.dumps({"envelope": {"tool": "AuthWatch"}}), encoding="utf-8")
    with pytest.raises(ConfigError):
        check(big, inp)


def test_output_paths_must_differ(inp, tmp_path):
    with pytest.raises(ConfigError):
        check(tmp_path / "a.out", inp, others=[tmp_path / "a.out"])
    check(tmp_path / "a.out", inp, others=[tmp_path / "b.out"])


def test_write_failure_leaves_original_intact(tmp_path, monkeypatch):
    """Case 58: a write that fails midway leaves the previous file intact and no temp file."""
    target = tmp_path / "r.json"
    target.write_bytes(b"original")

    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OperationalError):
        write_atomic(target, b"new content")
    assert target.read_bytes() == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_replace_onto_open_file(tmp_path, monkeypatch):
    """Case 76: os.replace failing (as on Windows when the destination is open elsewhere) ->
    OperationalError (exit 4); the original is untouched."""
    target = tmp_path / "r.json"
    target.write_bytes(b"original")

    def denied(*_a, **_k):
        raise PermissionError("in use")

    monkeypatch.setattr(os, "replace", denied)
    with pytest.raises(OperationalError) as info:
        write_atomic(target, b"new")
    assert info.value.exit_code == 4
    assert target.read_bytes() == b"original"
    assert [p.name for p in tmp_path.iterdir()] == ["r.json"]


def test_write_atomic_writes(tmp_path):
    target = tmp_path / "r.json"
    write_atomic(target, b"abc\n")
    assert target.read_bytes() == b"abc\n"
    if not IS_WINDOWS:
        assert target.stat().st_mode & 0o777 == 0o600


def test_check_input(tmp_path):
    """Case 16: a missing input path or a directory -> ConfigError (exit 2)."""
    with pytest.raises(ConfigError):
        check_input(tmp_path / "nope.jsonl")
    with pytest.raises(ConfigError):
        check_input(tmp_path)
