from gevent._socketcommon import wait_read, wait_write  # type:ignore
from peewee import PostgresqlDatabase
from psycopg2 import extensions

db = PostgresqlDatabase(None)


# Call this function after monkey-patching socket
def patch_psycopg2():
    extensions.set_wait_callback(_psycopg2_gevent_callback)


def _psycopg2_gevent_callback(conn, timeout=None):
    while True:
        state = conn.poll()
        if state == extensions.POLL_OK:
            break
        if state == extensions.POLL_READ:
            wait_read(conn.fileno(), timeout=timeout)
        elif state == extensions.POLL_WRITE:
            wait_write(conn.fileno(), timeout=timeout)
        else:
            raise ValueError('poll() returned unexpected result')
