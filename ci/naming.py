#!/usr/bin/env python3
import os
import re
import subprocess
import sys

TYPES = ["feat", "fix", "perf", "refactor", "test", "docs", "build", "ci", "chore", "revert"]
SCOPES = [
    "model", "normalize", "fingerprint", "dedup", "correlate", "lifecycle", "enrich", "risk",
    "parsers", "pipeline", "ingest", "processing", "feeds", "reachability", "assets", "api",
    "collectors", "migrations", "deploy", "observability", "bench", "ci", "docs", "adr", "repo",
]
MAX_BRANCH = 50
MAX_SUBJECT = 72

TYPES_RE = "|".join(TYPES)
SCOPES_RE = "|".join(SCOPES)
BRANCH_RE = re.compile(rf"^({TYPES_RE})/([0-9]+|adr-[0-9]{{4}})-[a-z0-9]+(-[a-z0-9]+)*$")
RELEASE_RE = re.compile(r"^release/[0-9]+\.[0-9]+$")
HOTFIX_RE = re.compile(r"^hotfix/[0-9]+\.[0-9]+\.[0-9]+-[a-z0-9]+(-[a-z0-9]+)*$")
SUBJECT_RE = re.compile(rf"^({TYPES_RE})(\(({SCOPES_RE})(/[a-z0-9._-]+)?\))?!?: .+")
BAD_CHARS_RE = re.compile(r"[^a-z0-9/-]")


def git(*args):
    result = subprocess.run(["git", *args], capture_output=True, text=True)
    return result.returncode, result.stdout.strip()


def check_branch(branch):
    errors = []
    if branch in ("main", "master"):
        return errors
    if branch.startswith("release/"):
        if not RELEASE_RE.match(branch):
            errors.append(f"ветка релиза: release/<major>.<minor>, получено: {branch}")
        return errors
    if branch.startswith("hotfix/"):
        if not HOTFIX_RE.match(branch):
            errors.append(f"ветка хотфикса: hotfix/<major>.<minor>.<patch>-<slug>, получено: {branch}")
        return errors
    if not BRANCH_RE.match(branch):
        errors.append(f"имя ветки: <type>/<issue>-<slug> или <type>/adr-<NNNN>-<slug>, получено: {branch}")
        errors.append(f"   допустимые type: {', '.join(TYPES)}")
        errors.append("   пример: feat/142-dedup-simhash-blocking")
    if len(branch) > MAX_BRANCH:
        errors.append(f"имя ветки длиннее {MAX_BRANCH} символов ({len(branch)}): {branch}")
    if BAD_CHARS_RE.search(branch):
        errors.append(f"в имени ветки только строчная латиница, цифры, дефис и слеш: {branch}")
    return errors


def check_subject(subject, source):
    errors = []
    if not subject or subject.startswith(("Merge ", "Revert ")):
        return errors
    if not SUBJECT_RE.match(subject):
        errors.append(f"{source}: ожидается '<type>(<scope>): описание', получено: {subject}")
        errors.append(f"   допустимые scope: {', '.join(SCOPES)}")
    head = subject.split("\n", 1)[0]
    if len(head) > MAX_SUBJECT:
        errors.append(f"{source}: заголовок длиннее {MAX_SUBJECT} символов ({len(head)})")
    if head.endswith("."):
        errors.append(f"{source}: заголовок не заканчивается точкой")
    return errors


def current_branch():
    code, out = git("rev-parse", "--abbrev-ref", "HEAD")
    return out if code == 0 else ""


def commit_subjects(base_ref):
    code, _ = git("rev-parse", "--verify", base_ref)
    if code != 0:
        return None
    _, out = git("log", "--format=%s", f"{base_ref}..HEAD")
    return [line for line in out.splitlines() if line]


def main():
    errors = []

    branch = os.environ.get("BRANCH") or current_branch()
    if branch and branch != "HEAD":
        print(f"== ветка: {branch}")
        errors += check_branch(branch)
    else:
        print("== ветка не определена, проверка пропущена")

    pr_title = os.environ.get("PR_TITLE", "")
    msg_file = os.environ.get("COMMIT_MSG_FILE", "")
    base_ref = os.environ.get("BASE_REF", "")
    if pr_title:
        print("== заголовок PR")
        errors += check_subject(pr_title, "заголовок PR")
    elif msg_file:
        print("== сообщение коммита")
        with open(msg_file, encoding="utf-8") as f:
            errors += check_subject(f.readline().rstrip("\n"), "сообщение коммита")
    elif base_ref:
        subjects = commit_subjects(base_ref)
        if subjects is not None:
            print("== коммиты ветки")
            for subject in subjects:
                errors += check_subject(subject, "коммит")

    if errors:
        print("\n".join(errors))
        print("\nnaming: ЕСТЬ ЗАМЕЧАНИЯ")
        return 1
    print("naming: чисто")
    return 0


if __name__ == "__main__":
    sys.exit(main())
