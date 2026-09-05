#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

MAX="${PR_MAX_LINES:-500}"
BASE="${BASE_REF:-origin/main}"
EXEMPT="${SIZE_EXEMPT:-0}"

EXCLUDE=(
  ':(exclude)**/go.sum'
  ':(exclude)**/*.sum'
  ':(exclude)**/*.lock'
  ':(exclude)vendor/**'
  ':(exclude)testdata/**'
  ':(exclude)**/*.pb.go'
  ':(exclude)**/*_gen.go'
  ':(exclude)**/gen/**'
  ':(exclude).github/rulesets/**'
)

if ! git rev-parse --verify "$BASE" >/dev/null 2>&1; then
  echo "база $BASE недоступна — проверка размера PR пропущена"
  exit 0
fi

stat=$(git diff --shortstat "$BASE"...HEAD -- . "${EXCLUDE[@]}" || true)
added=$(grep -oE '[0-9]+ insertion' <<<"$stat" | grep -oE '[0-9]+' || echo 0)
deleted=$(grep -oE '[0-9]+ deletion' <<<"$stat" | grep -oE '[0-9]+' || echo 0)
total=$((added + deleted))

echo "изменено строк (без generated/lock/testdata): $total (+$added -$deleted), лимит: $MAX"

if [ "$total" -le "$MAX" ]; then
  echo "pr-size: чисто"
  exit 0
fi

if [ "$EXEMPT" = "1" ]; then
  echo "pr-size: превышение ($total > $MAX), но PR помечен label 'size-exempt' — пропускаю"
  exit 0
fi

echo
echo "PR превышает лимит в $MAX строк (сейчас $total)."
echo "Раздели на несколько PR по границам стадий/модулей."
echo "Если изменение неделимо (массовая генерация, переименование) — добавь label 'size-exempt'."
exit 1
