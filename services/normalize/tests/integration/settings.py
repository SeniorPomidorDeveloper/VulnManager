import pathlib

SERVICE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPO_DIR = SERVICE_DIR.parents[1]
MIGRATIONS_DIR = REPO_DIR / 'db'

DATABASE = 'vulnmanager'
