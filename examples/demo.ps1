# AuthWatch demo: a clean run, an alerts run, an incomplete run, and the inspection commands.
# Usage: examples\demo.ps1 [-Work <dir>]   (default: current directory)
# Requires AuthWatch installed:  python -m pip install -e ".[dev]"
param([string]$Work = (Get-Location).Path)
$Repo = Split-Path -Parent $PSScriptRoot
$env:PYTHONUTF8 = "1"
New-Item -ItemType Directory -Force (Join-Path $Work "samples"), (Join-Path $Work "out") | Out-Null
python (Join-Path $Repo "samples\make_samples.py") (Join-Path $Work "samples")

"### clean.jsonl (expect exit 0)"
python -m authwatch analyze (Join-Path $Work "samples\clean.jsonl")
"exit $LASTEXITCODE"

"### attacks.jsonl (expect exit 1)"
python -m authwatch analyze (Join-Path $Work "samples\attacks.jsonl") --report (Join-Path $Work "out\report.json") --force-report
"exit $LASTEXITCODE"

"### broken.jsonl (expect exit 4)"
python -m authwatch analyze (Join-Path $Work "samples\broken.jsonl")
"exit $LASTEXITCODE"

"### explain the AW-004 alert (expect exit 0)"
python -m authwatch explain 9e00a620 --report (Join-Path $Work "out\report.json") --input (Join-Path $Work "samples\attacks.jsonl")
"exit $LASTEXITCODE"

"### validate broken.jsonl (expect exit 4)"
python -m authwatch validate (Join-Path $Work "samples\broken.jsonl")
"exit $LASTEXITCODE"

"### rules"
python -m authwatch rules

"### attacks report as JSON (first lines)"
# Windows PowerShell 5.1 re-encodes text piped between two native programs (and may add a
# BOM), so pretty-print the report file instead of piping authwatch into json.tool.
python -m json.tool (Join-Path $Work "out\report.json") | Select-Object -First 20
