#!/usr/bin/env bash
set -euo pipefail
PYTHON=${PYTHON:-python3}
echo "Create virtualenv (optional) and install requirements:"
echo "$PYTHON -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt"
echo "Run training (requires flows CSV) or start orchestrator with an existing model. Example:"
echo "./scripts/run_local.sh start"

if [[ ${1:-} == "start" ]]; then
  echo "Starting orchestrator cycle (dry-run)"
  .venv/bin/python -m src.orchestrator --iface en0 --duration 10
fi
