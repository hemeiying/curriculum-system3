
from contextlib import contextmanager
from psycopg2.pool import ThreadedConnectionPool

dsn = "host=localhost dbname=STUDENT user=testuser password=pass"
db_pool = ThreadedConnectionPool(minconn=2, maxconn=10, dsn=dsn)


@contextmanager
def db_block():
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cur:
            yield cur
            conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        db_pool.putconn(conn)
