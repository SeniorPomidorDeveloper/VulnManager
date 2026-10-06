#!/usr/bin/env python3
import json
import pathlib
import shutil
import subprocess
import sys

REPO = "repos/{owner}/{repo}"
ROOT = pathlib.Path(__file__).resolve().parent.parent


def gh(*args, check=True):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=check)


def main():
    if shutil.which("gh") is None:
        print("нужен gh CLI: https://cli.github.com/")
        return 1
    if gh("auth", "status", check=False).returncode != 0:
        print("выполни: gh auth login")
        return 1

    print("== merge button")
    gh(
        "api", "-X", "PATCH", REPO,
        "-F", "allow_squash_merge=true",
        "-F", "allow_merge_commit=false",
        "-F", "allow_rebase_merge=false",
        "-F", "delete_branch_on_merge=true",
        "-F", "allow_auto_merge=true",
    )
    print("   squash-only, auto-delete веток после мержа")

    print("== rulesets")
    existing = {r["name"]: r["id"] for r in json.loads(gh("api", f"{REPO}/rulesets").stdout)}
    for path in sorted((ROOT / ".github" / "rulesets").glob("*.json")):
        name = json.loads(path.read_text(encoding="utf-8"))["name"]
        if name in existing:
            gh("api", "-X", "PUT", f"{REPO}/rulesets/{existing[name]}", "--input", str(path))
            print(f"   обновлён: {name} (id={existing[name]})")
        else:
            gh("api", "-X", "POST", f"{REPO}/rulesets", "--input", str(path))
            print(f"   создан: {name}")

    print("готово — сверь Settings -> Rules в вебе")
    return 0


if __name__ == "__main__":
    sys.exit(main())
