#!/usr/bin/env bash
# TrustVault Production Build Script
set -o errexit

if [ -f ".venv/bin/python" ]; then
    PYTHON_CMD=".venv/bin/python"
elif [ -f "../.venv/bin/python" ]; then
    PYTHON_CMD="../.venv/bin/python"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
else
    PYTHON_CMD="python"
fi

echo "==> Using Python: $($PYTHON_CMD --version)"

echo "==> Collecting static assets..."
$PYTHON_CMD manage.py collectstatic --no-input

echo "==> Applying database migrations..."
$PYTHON_CMD manage.py migrate --no-input

echo "==> Build complete."
