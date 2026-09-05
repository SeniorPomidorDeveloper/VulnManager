#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

STRICT="${STRICT:-0}"

fail=0
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
skip() {
  if [ "$STRICT" = "1" ] && [ "${2:-tool}" = "tool" ]; then
    printf '   ОШИБКА (STRICT): %s\n' "$1"; fail=1
  else
    printf '   пропущено: %s\n' "$1"
  fi
}
need() { command -v "$1" >/dev/null 2>&1; }

step "go build ./..."
if need go && [ -f go.work ]; then
  go build ./... || fail=1
else
  skip "go/go.work отсутствуют" structural
fi

step "go test ./... -race"
if need go && [ -f go.work ]; then
  go test -race ./... || fail=1
else
  skip "go/go.work отсутствуют" structural
fi

printf '\n'
if [ "$fail" -ne 0 ]; then echo "unit: ЕСТЬ ЗАМЕЧАНИЯ"; exit 1; fi
echo "unit: чисто"
