import psycopg2

QUEUE_OWNER_ROLE = 'ingest_queue_owner'
QUEUE_CONSUMER_ROLE = 'queue_consumer'
QUEUE_CLIENT_ROLE = 'queue_client'

ROLES = (
    (QUEUE_OWNER_ROLE, 'NOLOGIN BYPASSRLS'),
    (QUEUE_CONSUMER_ROLE, 'NOLOGIN'),
    (QUEUE_CLIENT_ROLE, f'LOGIN IN ROLE {QUEUE_CONSUMER_ROLE}'),
)


def create_cluster_roles(conninfo):
    conn = psycopg2.connect(conninfo.get_dsn())
    conn.autocommit = True
    cursor = conn.cursor()
    for role, options in ROLES:
        cursor.execute(f'DROP ROLE IF EXISTS {role}')
        cursor.execute(f'CREATE ROLE {role} {options}')
    conn.close()
