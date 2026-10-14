import psycopg2
import pytest

from finding_sql import INSERT_FINDING_SEVERITY

LOW = 'low'
ORDER = ('info', 'unknown', LOW, 'medium', 'high', 'critical')


@pytest.mark.parametrize('rank', range(len(ORDER)))
def test_rank_follows_the_severity_order(cursor, run_id, rank):
    cursor.execute(INSERT_FINDING_SEVERITY, (run_id, ORDER[rank]))

    cursor.execute('SELECT severity_rank FROM finding')

    assert cursor.fetchone()[0] == rank + 1


def test_sorting_by_rank_puts_critical_first(cursor, run_id):
    for severity in (LOW, 'critical', 'info', 'high'):
        cursor.execute(INSERT_FINDING_SEVERITY, (run_id, severity))

    cursor.execute('SELECT severity FROM finding ORDER BY severity_rank DESC')

    assert [row[0] for row in cursor.fetchall()] == [
        'critical', 'high', LOW, 'info',
    ]


def test_rank_cannot_be_written(cursor, run_id):
    cursor.execute(INSERT_FINDING_SEVERITY, (run_id, LOW))

    with pytest.raises(psycopg2.errors.GeneratedAlways):
        cursor.execute('UPDATE finding SET severity_rank = 6')
