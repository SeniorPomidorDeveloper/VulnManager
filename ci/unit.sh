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

gomods=$(find . -name go.mod -not -path './vendor/*' 2>/dev/null | sort)

step "go build ./..."
if ! need go || [ ! -f go.work ]; then
  skip "go/go.work отсутствуют" structural
elif [ -z "$gomods" ]; then
  skip "Go-модулей ещё нет" structural
else
  while IFS= read -r gomod; do
    moddir=$(dirname "$gomod")
    (cd "$moddir" && go build ./...) || fail=1
  done <<< "$gomods"
fi

step "go test ./... -race"
if ! need go || [ ! -f go.work ]; then
  skip "go/go.work отсутствуют" structural
elif [ -z "$gomods" ]; then
  skip "Go-модулей ещё нет" structural
else
  while IFS= read -r gomod; do
    moddir=$(dirname "$gomod")
    (cd "$moddir" && go test -race ./...) || fail=1
  done <<< "$gomods"
fi

printf '\n'
if [ "$fail" -ne 0 ]; then echo "unit: ЕСТЬ ЗАМЕЧАНИЯ"; exit 1; fi
echo "unit: чисто"
