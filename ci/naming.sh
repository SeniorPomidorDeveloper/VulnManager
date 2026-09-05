#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

TYPES='feat|fix|perf|refactor|test|docs|build|ci|chore|revert'
SCOPES='model|normalize|fingerprint|dedup|correlate|lifecycle|enrich|risk|parsers|pipeline|ingest|processing|feeds|reachability|assets|api|collectors|migrations|deploy|observability|bench|ci|docs|adr|repo'
MAXLEN_BRANCH=50
MAXLEN_SUBJECT=72

fail=0
err() { printf '\033[31m%s\033[0m\n' "$1"; fail=1; }

check_branch() {
  local b="$1"
  case "$b" in
    main|master) return 0 ;;
    release/*)
      [[ "$b" =~ ^release/[0-9]+\.[0-9]+$ ]] || err "ветка релиза: release/<major>.<minor>, получено: $b"
      return 0 ;;
    hotfix/*)
      [[ "$b" =~ ^hotfix/[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]+(-[a-z0-9]+)*$ ]] \
        || err "ветка хотфикса: hotfix/<major>.<minor>.<patch>-<slug>, получено: $b"
      return 0 ;;
  esac

  if [[ ! "$b" =~ ^($TYPES)/([0-9]+|adr-[0-9]{4})-[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
    err "имя ветки: <type>/<issue>-<slug> или <type>/adr-<NNNN>-<slug>, получено: $b"
    printf '   допустимые type: %s\n' "${TYPES//|/, }"
    printf '   пример: feat/142-dedup-simhash-blocking\n'
  fi
  if [ "${#b}" -gt "$MAXLEN_BRANCH" ]; then
    err "имя ветки длиннее $MAXLEN_BRANCH символов (${#b}): $b"
  fi
  if [[ "$b" =~ [^a-z0-9/-] ]]; then
    err "в имени ветки только строчная латиница, цифры, дефис и слеш: $b"
  fi
}

check_subject() {
  local s="$1" src="$2"
  [ -n "$s" ] || return 0
  case "$s" in
    "Merge "*|"Revert "*) return 0 ;;
  esac
  if [[ ! "$s" =~ ^($TYPES)(\(($SCOPES)(/[a-z0-9._-]+)?\))?!?:\ .+ ]]; then
    err "$src: ожидается '<type>(<scope>): описание', получено: $s"
    printf '   допустимые scope: %s\n' "${SCOPES//|/, }"
  fi
  local head="${s%%$'\n'*}"
  if [ "${#head}" -gt "$MAXLEN_SUBJECT" ]; then
    err "$src: заголовок длиннее $MAXLEN_SUBJECT символов (${#head})"
  fi
  if [[ "$head" =~ \.$ ]]; then
    err "$src: заголовок не заканчивается точкой"
  fi
}

branch="${BRANCH:-}"
if [ -z "$branch" ] && command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
fi
if [ -n "$branch" ] && [ "$branch" != "HEAD" ]; then
  printf '\033[1m== ветка: %s\033[0m\n' "$branch"
  check_branch "$branch"
else
  printf '== ветка не определена, проверка пропущена\n'
fi

if [ -n "${PR_TITLE:-}" ]; then
  printf '\033[1m== заголовок PR\033[0m\n'
  check_subject "$PR_TITLE" "заголовок PR"
elif [ -n "${COMMIT_MSG_FILE:-}" ]; then
  printf '\033[1m== сообщение коммита\033[0m\n'
  check_subject "$(head -1 "$COMMIT_MSG_FILE")" "сообщение коммита"
elif [ -n "${BASE_REF:-}" ] && git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  printf '\033[1m== коммиты ветки\033[0m\n'
  while IFS= read -r line; do
    [ -n "$line" ] && check_subject "$line" "коммит"
  done < <(git log --format=%s "$BASE_REF..HEAD")
fi

if [ "$fail" -ne 0 ]; then echo; echo "naming: ЕСТЬ ЗАМЕЧАНИЯ"; exit 1; fi
echo "naming: чисто"
