import pathlib

import psycopg2
import pytest

from settings import DATABASE, MIGRATIONS_DIR

TENANT_TABLES = ('tenant', 'product', 'ingest_job', 'raw_blob')
SCRATCH_DATABASE = 'ingest_upgrade_check'
UPGRADE_VERSION = 'V0004'


def versions():
    return sorted((MIGRATIONS_DIR / DATABASE / 'migrations').glob('V*.sql'))


def split_at_upgrade():
    paths = versions()
    index = next(
        position
        for position, path in enumerate(paths)
        if path.name.startswith(UPGRADE_VERSION)
    )
    return paths[:index], paths[index]


def test_rls_is_forced_on_all_tables(pgsql):
    cursor = pgsql[DATABASE].cursor()
    cursor.execute(
        'SELECT relname, relrowsecurity, relforcerowsecurity '
        'FROM pg_class WHERE relname = ANY(%s)',
        (list(TENANT_TABLES),),
    )

    expected = sorted((name, True, True) for name in TENANT_TABLES)
    assert sorted(cursor.fetchall()) == expected


@pytest.fixture
def scratch_database(pgsql):
    admin = pgsql[DATABASE].conn
    admin.autocommit = True
    cursor = admin.cursor()
    cursor.execute(f'DROP DATABASE IF EXISTS {SCRATCH_DATABASE}')
    cursor.execute(f'CREATE DATABASE {SCRATCH_DATABASE}')
    conninfo = pgsql[DATABASE].conninfo.replace(dbname=SCRATCH_DATABASE)
    conn = psycopg2.connect(conninfo.get_dsn())
    conn.autocommit = True
    yield conn
    conn.close()
    cursor.execute(f'DROP DATABASE {SCRATCH_DATABASE}')


def apply(conn, path: pathlib.Path):
    conn.cursor().execute(path.read_text(encoding='utf-8'))


def test_upgrade_keeps_existing_jobs(scratch_database):
    previous, upgrade = split_at_upgrade()
    for path in previous:
        apply(scratch_database, path)
    cursor = scratch_database.cursor()
    cursor.execute(
        'INSERT INTO ingest_job '
        '(tenant_id, scope_key, raw_key, tool, sha256, scan_id) '
        "VALUES ('acme', 'scope', 'acme/scan/sha', 'trivy', 'sha', 'scan')",
    )

    apply(scratch_database, upgrade)

    cursor.execute(
        'SELECT tenant_id, raw_key, state, product_id FROM ingest_job',
    )
    assert cursor.fetchall() == [('acme', 'acme/scan/sha', 'pending', '')]
