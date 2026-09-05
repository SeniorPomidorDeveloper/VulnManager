#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v gh >/dev/null 2>&1; then
  echo "нужен gh CLI: https://cli.github.com/"; exit 1
fi
gh auth status >/dev/null 2>&1 || { echo "выполни: gh auth login"; exit 1; }

echo "== merge button"
gh api -X PATCH "repos/{owner}/{repo}" \
  -F allow_squash_merge=true \
  -F allow_merge_commit=false \
  -F allow_rebase_merge=false \
  -F delete_branch_on_merge=true \
  -F allow_auto_merge=true \
  >/dev/null
echo "   squash-only, auto-delete веток после мержа"

echo "== rulesets"
for file in .github/rulesets/*.json; do
  name=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['name'])" "$file")
  existing_id=$(gh api "repos/{owner}/{repo}/rulesets" --jq \
    ".[] | select(.name==\"$name\") | .id" 2>/dev/null || true)
  if [ -n "$existing_id" ]; then
    gh api -X PUT "repos/{owner}/{repo}/rulesets/$existing_id" --input "$file" >/dev/null
    echo "   обновлён: $name (id=$existing_id)"
  else
    gh api -X POST "repos/{owner}/{repo}/rulesets" --input "$file" >/dev/null
    echo "   создан: $name"
  fi
done

echo "готово — сверь Settings -> Rules в вебе"
