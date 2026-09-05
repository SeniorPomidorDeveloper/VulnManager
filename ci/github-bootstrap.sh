#!/usr/bin/env bash
set -euo pipefail

if ! command -v gh >/dev/null 2>&1; then
  echo "нужен gh CLI: https://cli.github.com/"; exit 1
fi
gh auth status >/dev/null 2>&1 || { echo "выполни: gh auth login"; exit 1; }

TYPES='feat fix perf refactor test docs build ci chore revert'
SCOPES='model normalize fingerprint dedup correlate lifecycle enrich risk parsers pipeline ingest processing feeds reachability assets api collectors migrations deploy observability bench ci docs adr repo'

echo "== labels: type:*"
for t in $TYPES; do
  gh label create "type:$t" --color "1d76db" --force >/dev/null
done

echo "== labels: scope:*"
for s in $SCOPES; do
  gh label create "scope:$s" --color "0e8a16" --force >/dev/null
done

echo "== labels: служебные"
gh label create "adr-proposal"   --color "5319e7" --description "Требует ADR перед реализацией" --force >/dev/null
gh label create "good-first-issue" --color "7057ff" --force >/dev/null
gh label create "blocked"        --color "b60205" --description "Ждёт внешнего решения" --force >/dev/null
gh label create "full-ci"        --color "fbca04" --description "Требует полного прогона CI перед мержем" --force >/dev/null
gh label create "size-exempt"    --color "c5def5" --description "Неделимое изменение — пропустить лимит строк в PR" --force >/dev/null

echo "== milestones: фазы плана"
declare -A MS=(
  ["Фаза 0: каркас (v0.0.1)"]="Репозиторий, CI, пустой сервис, .deb"
  ["Фаза 1: сквозной срез (v0.1.0)"]="Отчёт доезжает от HTTP до записи в БД и обратно, без дедупа"
  ["Фаза 2: отпечатки и дедуп"]="fingerprint L0-L2, dedup, golden-корпус"
  ["Фаза 3: учёт и жизненный цикл (v0.2.0)"]="correlate, lifecycle, reconciliation, триаж"
  ["Фаза 4: каталоги и риск (v0.3.0)"]="advisory-модель, feeds, enrich, risk"
  ["Фаза 5: качество и бенчмарк"]="bench harness, сравнение с DefectDojo, quality gate"
  ["Фаза 6: поставка (v1.0.0)"]="Helm, release flow, observability, partitioning"
  ["Фаза 7: расширение"]="collectors, assets, reachability, analytics — по потребности"
)
for name in "${!MS[@]}"; do
  gh api repos/:owner/:repo/milestones -f title="$name" -f description="${MS[$name]}" \
    >/dev/null 2>&1 || echo "   уже существует: $name"
done

echo "== projects"
echo "   создай вручную один раз: gh project create --owner @me --title 'VulnManager'"
echo "   поля Status по умолчанию (Backlog/In Progress/In Review/Done) обычно достаточно"

echo "готово"
