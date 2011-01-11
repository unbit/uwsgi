import psycopg2

def pg_wait(conn, env, timeout=0):
        while 1:
                state = conn.poll()
                if state == psycopg2.extensions.POLL_OK:
                        raise StopIteration
                elif state == psycopg2.extensions.POLL_WRITE:
                        yield env['x-wsgiorg.fdevent.writable'](conn.fileno(), timeout)
                elif state == psycopg2.extensions.POLL_READ:
                        yield env['x-wsgiorg.fdevent.readable'](conn.fileno(), timeout)
                else:
                        raise psycopg2.OperationalError("poll() returned %s" % state)


def application(env, start_response):

        start_response('200 OK', [('Content-Type', 'text/html')])

        connection = psycopg2.connect(database='uwsgi',user='uwsgi',password='uwsgi',host='192.168.173.100', async=1)

        for i in pg_wait(connection, env, 3):
                yield i

        print "connected"
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM foo")

        for i in pg_wait(cursor.connection, env, 3):
                yield i

        print "query result available"

        for record in cursor:
                yield str(record)

        connection.close()
