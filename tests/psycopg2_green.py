# uwsgi --async 1000 --ugreen
import uwsgi
import psycopg2

def async_wait(conn):
	# conn can be a connection or a cursor
	if not hasattr(conn, 'poll'):
		conn = conn.connection
	
	# interesting part: suspend until ready
	while True:
		state = conn.poll()
		if state == psycopg2.extensions.POLL_OK:
			break
		elif state == psycopg2.extensions.POLL_READ:
			uwsgi.wait_fd_read(conn.fileno())
                        uwsgi.suspend()
		elif state == psycopg2.extensions.POLL_WRITE:
			uwsgi.wait_fd_write(conn.fileno())
                        uwsgi.suspend()
		else:
			raise Exception("Unexpected result from poll: %r", state)

			



def application(env, start_response):

	start_response('200 Ok', [('Content-type', 'text/html')])

	conn = psycopg2.connect("dbname=template1 user=postgres", async=True)

	# suspend until connection
	async_wait(conn)

	curs = conn.cursor()

	yield "<table>"

	curs.execute("SELECT * FROM tests")

	# suspend until result
	async_wait(curs)

	while True:
		row = curs.fetchone()
		if not row: break
		yield "<tr><td>%s</td></tr>" % str(row)

	yield "</table>"

	conn.close()
