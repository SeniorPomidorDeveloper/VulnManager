import psycopg2
import pytest

from finding_sql import INSERT_FINDING, INSERT_FINDING_VULN


def test_finding_without_vuln_id_stores_nulls(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))

    cursor.execute('SELECT vuln_source, vuln_id FROM finding')

    assert cursor.fetchone() == (None, None)


def test_finding_stores_vuln_id_with_source(cursor, run_id):
    cursor.execute(INSERT_FINDING_VULN, (run_id, 'cve', 'CVE-2021-0001'))

    cursor.execute('SELECT vuln_source, vuln_id FROM finding')

    assert cursor.fetchone() == ('cve', 'CVE-2021-0001')


@pytest.mark.parametrize('pair', [('cve', None), (None, 'CVE-2021-0001')])
def test_vuln_source_and_id_come_together(cursor, run_id, pair):
    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_FINDING_VULN, (run_id, *pair))
