import psycopg2

import settings

ROLES = (
    (settings.QUEUE_OWNER_ROLE, 'NOLOGIN BYPASSRLS'),
    (settings.QUEUE_CONSUMER_ROLE, 'NOLOGIN'),
    (
        settings.QUEUE_CLIENT_ROLE,
        f'LOGIN IN ROLE {settings.QUEUE_CONSUMER_ROLE}',
    ),
)


def create_cluster_roles(conninfo):
    conn = psycopg2.connect(conninfo.get_dsn())
    conn.autocommit = True
    cursor = conn.cursor()
    for role, options in ROLES:
        cursor.execute(f'DROP ROLE IF EXISTS {role}')
        cursor.execute(f'CREATE ROLE {role} {options}')
    conn.close()
