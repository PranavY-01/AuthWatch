#!/usr/bin/env bash
# AuthWatch demo: a clean run, an alerts run and an incomplete run.
# Usage: examples/demo.sh [WORK_DIR]   (default: current directory)
# Requires AuthWatch installed:  python -m pip install -e ".[dev]"
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PWD}"
PY="${PYTHON:-python}"

mkdir -p "$WORK/samples" "$WORK/out"
"$PY" "$REPO/samples/make_samples.py" "$WORK/samples"

echo "### clean.jsonl (expect exit 0)"
"$PY" -m authwatch analyze "$WORK/samples/clean.jsonl"
echo "exit $?"
echo
echo "### attacks.jsonl (expect exit 1)"
"$PY" -m authwatch analyze "$WORK/samples/attacks.jsonl" --report "$WORK/out/report.json" --force-report
echo "exit $?"
echo
echo "### broken.jsonl (expect exit 4)"
"$PY" -m authwatch analyze "$WORK/samples/broken.jsonl"
echo "exit $?"
echo
echo "### attacks.jsonl as JSON (first lines)"
"$PY" -m authwatch analyze "$WORK/samples/attacks.jsonl" --format json | "$PY" -m json.tool | head -n 20
