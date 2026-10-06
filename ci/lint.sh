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
SKIP_REPO_CHECKS="${SKIP_REPO_CHECKS:-0}"
repo_check_skipped() { [ "$SKIP_REPO_CHECKS" = "1" ]; }

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

step "gofmt / gofumpt"
if need gofumpt; then
  out=$(gofumpt -l "$TARGET" || true)
elif need gofmt; then
  out=$(gofmt -l "$TARGET" || true)
else
  out=""; skip "gofmt не найден"
fi
if [ -n "$out" ]; then
  echo "Файлы не отформатированы:"; echo "$out"
  echo "Почини: gofumpt -w ."
  fail=1
fi

step "golangci-lint"
gomods=$(find "$TARGET" -name go.mod -not -path './vendor/*' 2>/dev/null | sort)
if [ -z "$gomods" ]; then
  skip "Go-модулей ещё нет" structural
elif need golangci-lint; then
  while IFS= read -r gomod; do
    moddir=$(dirname "$gomod")
    (cd "$moddir" && golangci-lint run ./...) || fail=1
  done <<< "$gomods"
else
  skip "golangci-lint не установлен"
fi

step "go mod tidy (без изменений)"
gomods_tidy=$(find "$TARGET" -name go.mod -not -path './vendor/*' 2>/dev/null | sort)
if ! need go; then
  skip "go отсутствует" structural
elif [ -z "$gomods_tidy" ]; then
  skip "Go-модулей ещё нет" structural
else
  while IFS= read -r gomod; do
    moddir=$(dirname "$gomod")
    (cd "$moddir" && go mod tidy) || fail=1
  done <<< "$gomods_tidy"
  if ! git diff --quiet -- "$TARGET"; then
    echo "go.mod/go.sum разошлись — выполни go mod tidy и закоммить"; fail=1
  fi
fi

step "контракты: buf"
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif [ -d api/proto ]; then
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
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif compgen -G "api/openapi/*.yaml" >/dev/null; then
  if need spectral; then
    spectral lint api/openapi/*.yaml || fail=1
  else
    skip "spectral не установлен"
  fi
else
  skip "api/openapi ещё нет" structural
fi

step "кодогенерация без расхождений"
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif [ -f buf.gen.yaml ] && need buf; then
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
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif need shellcheck; then
  shellcheck ci/*.sh || fail=1
else
  skip "shellcheck не установлен"
fi

step "версии зафиксированы (нет latest)"
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
else
  bad=$(grep -RnoE ':latest\b|@latest\b|ubuntu-latest\b' \
    --include='*.yaml' --include='*.yml' --include='Dockerfile' \
    .github docker deploy 2>/dev/null || true)
  if [ -n "$bad" ]; then
    echo "Найдены незафиксированные версии (latest):"
    echo "$bad"
    fail=1
  fi
fi

step "YAML"
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
else
  yaml_paths=()
  for d in data deploy .github; do
    [ -d "$d" ] && yaml_paths+=("$d")
  done
  if [ "${#yaml_paths[@]}" -eq 0 ]; then
    skip "нет каталогов для проверки YAML" structural
  elif need yamllint; then
    yamllint -s "${yaml_paths[@]}" || fail=1
  else
    skip "yamllint не установлен"
  fi
fi

step "миграции неизменяемы"
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif [ -d migrations ] && need git; then
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
if repo_check_skipped; then
  skip "репозиторный чек — не для этого workflow" structural
elif [ -d testdata/corpus ]; then
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
