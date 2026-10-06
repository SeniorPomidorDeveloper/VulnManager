#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

STRICT="${STRICT:-0}"
TARGET="${TARGET:-.}"

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

gomods=$(find "$TARGET" -name go.mod -not -path './vendor/*' 2>/dev/null | sort)

step "кодогенерация: sqlc"
sqlcyamls=$(find "$TARGET" -name sqlc.yaml -not -path './vendor/*' 2>/dev/null | sort)
if [ -z "$sqlcyamls" ]; then
  skip "sqlc.yaml ещё нет" structural
elif need sqlc; then
  while IFS= read -r cfg; do
    cfgdir=$(dirname "$cfg")
    (cd "$cfgdir" && sqlc generate) || fail=1
  done <<< "$sqlcyamls"
else
  skip "sqlc не установлен"
fi

step "go build ./..."
if ! need go; then
  skip "go отсутствует" structural
elif [ -z "$gomods" ]; then
  skip "Go-модулей ещё нет" structural
else
  while IFS= read -r gomod; do
    moddir=$(dirname "$gomod")
    (cd "$moddir" && go build ./...) || fail=1
  done <<< "$gomods"
fi

step "go test ./... -race"
if ! need go; then
  skip "go отсутствует" structural
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
