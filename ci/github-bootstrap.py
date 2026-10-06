#!/usr/bin/env python3
import shutil
import subprocess
import sys

TYPES = ["feat", "fix", "perf", "refactor", "test", "docs", "build", "ci", "chore", "revert"]
SCOPES = [
    "model", "normalize", "fingerprint", "dedup", "correlate", "lifecycle", "enrich", "risk",
    "parsers", "pipeline", "ingest", "processing", "feeds", "reachability", "assets", "api",
    "collectors", "migrations", "deploy", "observability", "bench", "ci", "docs", "adr", "repo",
]
SERVICE_LABELS = [
    ("adr-proposal", "5319e7", "Требует ADR перед реализацией"),
    ("good-first-issue", "7057ff", ""),
    ("blocked", "b60205", "Ждёт внешнего решения"),
    ("full-ci", "fbca04", "Требует полного прогона CI перед мержем"),
    ("size-exempt", "c5def5", "Неделимое изменение — пропустить лимит строк в PR"),
]
MILESTONES = {
    "Фаза 0: каркас (v0.0.1)": "Репозиторий, CI, пустой сервис, .deb",
    "Фаза 1: сквозной срез (v0.1.0)": "Отчёт доезжает от HTTP до записи в БД и обратно, без дедупа",
    "Фаза 2: отпечатки и дедуп": "fingerprint L0-L2, dedup, golden-корпус",
    "Фаза 3: учёт и жизненный цикл (v0.2.0)": "correlate, lifecycle, reconciliation, триаж",
    "Фаза 4: каталоги и риск (v0.3.0)": "advisory-модель, feeds, enrich, risk",
    "Фаза 5: качество и бенчмарк": "bench harness, сравнение с DefectDojo, quality gate",
    "Фаза 6: поставка (v1.0.0)": "Helm, release flow, observability, partitioning",
    "Фаза 7: расширение": "collectors, assets, reachability, analytics — по потребности",
}


def gh(*args, check=True):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=check)


def create_label(name, color, description=""):
    args = ["label", "create", name, "--color", color, "--force"]
    if description:
        args += ["--description", description]
    gh(*args)


def main():
    if shutil.which("gh") is None:
        print("нужен gh CLI: https://cli.github.com/")
        return 1
    if gh("auth", "status", check=False).returncode != 0:
        print("выполни: gh auth login")
        return 1

    print("== labels")
    for t in TYPES:
        create_label(f"type:{t}", "1d76db")
    for s in SCOPES:
        create_label(f"scope:{s}", "0e8a16")
    for name, color, description in SERVICE_LABELS:
        create_label(name, color, description)

    print("== milestones: фазы плана")
    for title, description in MILESTONES.items():
        result = gh(
            "api", "repos/:owner/:repo/milestones",
            "-f", f"title={title}", "-f", f"description={description}",
            check=False,
        )
        if result.returncode != 0:
            print(f"   уже существует: {title}")

    print("== projects")
    print("   создай вручную один раз: gh project create --owner @me --title 'VulnManager'")
    print("готово")
    return 0


if __name__ == "__main__":
    sys.exit(main())
