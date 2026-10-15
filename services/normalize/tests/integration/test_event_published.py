from finding_sql import INSERT_RUN, MARK_PUBLISHED, UNPUBLISHED

RUNNING = ('running',)


def test_run_is_unpublished_until_marked(cursor, run_id):
    cursor.execute(UNPUBLISHED)
    assert cursor.fetchone()[0] == 1

    cursor.execute(MARK_PUBLISHED, (run_id,))
    assert cursor.rowcount == 1

    cursor.execute(UNPUBLISHED)
    assert cursor.fetchone() == (0, 0)


def test_marking_twice_changes_nothing(cursor, run_id):
    cursor.execute(MARK_PUBLISHED, (run_id,))

    cursor.execute(MARK_PUBLISHED, (run_id,))

    assert cursor.rowcount == 0


def test_running_run_is_not_counted_or_marked(cursor):
    cursor.execute(INSERT_RUN, RUNNING)
    running_id = cursor.fetchone()[0]

    cursor.execute(MARK_PUBLISHED, (running_id,))
    assert cursor.rowcount == 0

    cursor.execute(UNPUBLISHED)
    assert cursor.fetchone()[0] == 0
