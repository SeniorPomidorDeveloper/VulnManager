#!/usr/bin/env python3
import os
import subprocess
import sys

EXCLUDE = [
    "**/go.sum", "**/*.sum", "**/*.lock", "vendor/**", "testdata/**", "**/*.pb.go",
    "**/*_gen.go", "**/gen/**", ".github/rulesets/**",
]


def main():
    limit = int(os.environ.get("PR_MAX_LINES", "500"))
    base = os.environ.get("BASE_REF", "origin/main")
    exempt = os.environ.get("SIZE_EXEMPT", "0") == "1"

    if subprocess.run(["git", "rev-parse", "--verify", base], capture_output=True).returncode != 0:
        print(f"база {base} недоступна — проверка размера PR пропущена")
        return 0

    pathspec = [".", *[f":(exclude){p}" for p in EXCLUDE]]
    out = subprocess.run(
        ["git", "diff", "--numstat", f"{base}...HEAD", "--", *pathspec],
        capture_output=True, text=True, check=True,
    ).stdout
    added = deleted = 0
    for line in out.splitlines():
        a, d, _ = line.split("\t", 2)
        if a != "-":
            added += int(a)
            deleted += int(d)
    total = added + deleted

    print(f"изменено строк (без generated/lock/testdata): {total} (+{added} -{deleted}), лимит: {limit}")
    if total <= limit:
        print("pr-size: чисто")
        return 0
    if exempt:
        print(f"pr-size: превышение ({total} > {limit}), но PR помечен label 'size-exempt' — пропускаю")
        return 0
    print(f"\nPR превышает лимит в {limit} строк (сейчас {total}).")
    print("Раздели на несколько PR по границам стадий/модулей.")
    print("Если изменение неделимо (массовая генерация, переименование) — добавь label 'size-exempt'.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
