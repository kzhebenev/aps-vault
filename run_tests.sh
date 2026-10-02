#!/bin/bash
# Backend tests in a throwaway container (no local venv needed).
#   ./run_tests.sh            — pytest
#   ./run_tests.sh audit      — pip-audit of runtime dependencies
set -e
cd "$(dirname "$0")"
IMG=python:3.11-slim
if [ "${1:-}" = audit ]; then
  docker run --rm -v "$PWD:/repo:ro" -w /repo/backend $IMG bash -c \
    "pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && pip-audit -r requirements.txt"
else
  docker run --rm -v "$PWD:/repo:ro" -w /repo/backend -e PYTHONDONTWRITEBYTECODE=1 $IMG bash -c \
    "pip install -q --root-user-action=ignore -r requirements-dev.txt >/dev/null && python -m pytest -q -p no:cacheprovider tests/"
fi
