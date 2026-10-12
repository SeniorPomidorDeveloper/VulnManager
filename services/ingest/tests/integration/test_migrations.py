import pathlib

import psycopg2
import pytest

from conftest import MIGRATIONS_DIR

INGEST = MIGRATIONS_DIR / 'ingest'
TENANT_TABLES = ['tenant', 'product', 'ingest_job', 'raw_blob']


def versions():
    return sorted(INGEST.glob('V*.sql'))


def test_row_level_security_is_forced_on_every_table(pgsql):
    cursor = pgsql['ingest'].cursor()
    cursor.execute(
        'SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = ANY(%s)',
        (TENANT_TABLES,),
    )

    assert sorted(cursor.fetchall()) == sorted((name, True, True) for name in TENANT_TABLES)


@pytest.fixture
def scratch_database(pgsql):
    admin = pgsql['ingest'].conn
    admin.autocommit = True
    name = 'ingest_upgrade_check'
    cursor = admin.cursor()
    cursor.execute(f'DROP DATABASE IF EXISTS {name}')
    cursor.execute(f'CREATE DATABASE {name}')
    conn = psycopg2.connect(pgsql['ingest'].conninfo.replace(dbname=name).get_dsn())
    conn.autocommit = True
    yield conn
    conn.close()
    cursor.execute(f'DROP DATABASE {name}')


def apply(conn, path: pathlib.Path):
    conn.cursor().execute(path.read_text(encoding='utf-8'))


def test_upgrade_from_previous_schema_keeps_existing_jobs(scratch_database):
    *previous, latest = versions()
    for path in previous:
        apply(scratch_database, path)
    cursor = scratch_database.cursor()
    cursor.execute(
        "INSERT INTO ingest_job (tenant_id, scope_key, raw_key) VALUES ('acme', 'scope', 'acme/scan/sha')",
    )

    apply(scratch_database, latest)

    cursor.execute('SELECT tenant_id, raw_key, state FROM ingest_job')
    assert cursor.fetchall() == [('acme', 'acme/scan/sha', 'pending')]
