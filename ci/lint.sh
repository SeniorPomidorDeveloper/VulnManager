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

step "gofmt / gofumpt"
if need gofumpt; then
  out=$(gofumpt -l . || true)
elif need gofmt; then
  out=$(gofmt -l . || true)
else
  out=""; skip "gofmt не найден"
fi
if [ -n "$out" ]; then
  echo "Файлы не отформатированы:"; echo "$out"
  echo "Почини: gofumpt -w ."
  fail=1
fi

step "golangci-lint"
if [ -z "$(find . -name go.mod -not -path './vendor/*' 2>/dev/null | head -1)" ]; then
  skip "Go-модулей ещё нет" structural
elif need golangci-lint; then
  golangci-lint run ./... || fail=1
else
  skip "golangci-lint не установлен"
fi

step "go mod tidy (без изменений)"
if need go && [ -f go.work ]; then
  go work sync
  if ! git diff --quiet -- '**/go.mod' '**/go.sum' 2>/dev/null; then
    echo "go.mod/go.sum разошлись — выполни go mod tidy и закоммить"; fail=1
  fi
else
  skip "go/go.work отсутствуют" structural
fi

step "контракты: buf"
if [ -d api/proto ]; then
  if need buf; then
    buf lint || fail=1
    buf format --diff --exit-code || { echo "proto не отформатирован: buf format -w"; fail=1; }
    if [ "${CHECK_BREAKING:-1}" = "1" ]; then
      buf breaking --against "${BUF_BASE:-.git#branch=main}" || fail=1
    fi
  else
    skip "buf не установлен"
  fi
else
  skip "api/proto ещё нет" structural
fi

step "контракты: OpenAPI"
if compgen -G "api/openapi/*.yaml" >/dev/null; then
  if need spectral; then
    spectral lint api/openapi/*.yaml || fail=1
  else
    skip "spectral не установлен"
  fi
else
  skip "api/openapi ещё нет" structural
fi

step "кодогенерация без расхождений"
if [ -f buf.gen.yaml ] && need buf; then
  buf generate
  if ! git diff --quiet; then
    echo "Сгенерированный код отличается от закоммиченного — выполни buf generate и закоммить"
    git --no-pager diff --stat
    fail=1
  fi
else
  skip "buf.gen.yaml отсутствует" structural
fi

step "shell-скрипты"
if need shellcheck; then
  shellcheck ci/*.sh || fail=1
else
  skip "shellcheck не установлен"
fi

step "версии зафиксированы (нет latest)"
bad=$(grep -RnoE ':latest\b|@latest\b|ubuntu-latest\b' \
  --include='*.yaml' --include='*.yml' --include='Dockerfile' \
  .github docker deploy 2>/dev/null || true)
if [ -n "$bad" ]; then
  echo "Найдены незафиксированные версии (latest):"
  echo "$bad"
  fail=1
fi

step "YAML"
if need yamllint; then
  yamllint -s data deploy .github 2>/dev/null || fail=1
else
  skip "yamllint не установлен"
fi

step "миграции неизменяемы"
if [ -d migrations ] && need git; then
  base="${BASE_REF:-origin/main}"
  if git rev-parse --verify "$base" >/dev/null 2>&1; then
    changed=$(git diff --diff-filter=MD --name-only "$base"...HEAD -- 'migrations/**' || true)
    if [ -n "$changed" ]; then
      echo "Изменены или удалены существующие миграции (правка запрещена, нужна новая версия):"
      echo "$changed"; fail=1
    fi
  else
    skip "база $base недоступна" structural
  fi
else
  skip "migrations ещё нет" structural
fi

step "в корпусе нет настоящих секретов"
if [ -d testdata/corpus ]; then
  if need gitleaks; then
    gitleaks dir testdata/corpus --no-banner || fail=1
  else
    skip "gitleaks не установлен"
  fi
else
  skip "testdata/corpus ещё нет" structural
fi

printf '\n'
if [ "$fail" -ne 0 ]; then echo "lint: ЕСТЬ ЗАМЕЧАНИЯ"; exit 1; fi
echo "lint: чисто"
