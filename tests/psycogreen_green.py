import uwsgi
import psycopg2


def ugreen_wait_callback(conn, timeout=-1):
    """A wait callback useful to allow uWSGI/uGreen to work with Psycopg."""
    while True:
        state = conn.poll()
        if state == psycopg2.extensions.POLL_OK:
            break
        elif state == psycopg2.extensions.POLL_READ:
            uwsgi.green_wait_fdread(conn.fileno())
        elif state == psycopg2.extensions.POLL_WRITE:
            uwsgi.green_wait_fdwrite(conn.fileno())
        else:
            raise Exception("Unexpected result from poll: %r", state)


# set the wait callback
psycopg2.extensions.set_wait_callback(ugreen_wait_callback)


def application(env, start_response):

    start_response('200 Ok', [('Content-type', 'text/html')])

    # connect
    conn = psycopg2.connect("dbname=prova user=postgres")
    # get cursor
    curs = conn.cursor()

    yield "<table>"

    # run query
    curs.execute("SELECT * FROM tests")

    while True:
        row = curs.fetchone()
        if not row:
            break
        yield "<tr><td>%s</td></tr>" % str(row)

    yield "</table>"

    conn.close()
