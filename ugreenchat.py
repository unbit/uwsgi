#!./uwsgi
import uwsgi

from bottle import route, default_app, request, response, redirect

@route('/')
def chat():
    return """<iframe src="/recv"></iframe>
    <iframe src="/sender"></iframe>"""

@route('/sender')
def sender():
    return """<form method="GET" action="/send">
<textarea name="message"></textarea><br/>
<input type="submit" value="send" />
</form>"""



@route('/recv')
def recv():
    response.header['Transfer-Encoding'] = 'chunked'

    # this will flush headers
    yield ""

    running = True
    while running:
        # this will put the core in pause (for max 10 seconds) and remove it from the sched queue, so the /send can write to its socket
        if not uwsgi.green_pause(10):
            running = False
        # this will maintain the connection opened if no data arrives
        yield "<span/>"


@route('/send')
def send():
    # this will write to all the core in PAUSED state
    uwsgi.green_write_all(request.GET['message'] + "<br/>")
    # this will unpause all the paused cores, so they will be re-inserted in the sched queue
    uwsgi.green_unpause_all()
    redirect('/sender')


application = default_app()
