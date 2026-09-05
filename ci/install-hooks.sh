#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
chmod +x hooks/*
git config core.hooksPath hooks
echo "хуки включены: core.hooksPath=hooks"
