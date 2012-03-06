import uwsgi

import time
import sys
import os


def application(env, start_response):
    print env
    start_response('200 OK', [('Content-Type', 'text/html')])

    yield '<h1>uWSGI %s status</h1>' % uwsgi.version
    yield 'masterpid: <b>' + str(uwsgi.masterpid()) + '</b><br/>'

    yield 'started on: <b>' + time.ctime(uwsgi.started_on) + '</b><br/>'

    yield 'buffer size: <b>' + str(uwsgi.buffer_size) + '</b><br/>'

    yield 'total_requests: <b>' + str(uwsgi.total_requests()) + '</b><br/>'

    yield 'log size: <b>' + str(uwsgi.logsize()) + '</b><br/>'

    yield 'workers: <b>' + str(uwsgi.numproc) + '</b><br/>'

    yield "cwd: <b>%s</b><br/>" % os.getcwd()

    try:
        yield "mode: <b>%s</b><br/>" % uwsgi.mode
    except:
        pass

    try:
        yield "pidfile: <b>%s</b><br/>" % uwsgi.pidfile
    except:
        pass

    yield "<h2>Hooks</h2>"

    for h in range(0,255):
        if uwsgi.has_hook(h):
            yield "%d<br/>" % h

    yield '<h2>dynamic options</h2>'

    yield '<b>logging</b>: ' + str(uwsgi.get_option(0)) + '<br/>'
    yield '<b>max_requests</b>: '  + str(uwsgi.getoption(1)) + '<br/>'
    yield '<b>socket_timeout</b>: ' + str(uwsgi.getoption(2)) + '<br/>'
    yield '<b>memory_debug</b>: ' + str(uwsgi.getoption(3)) + '<br/>'
    yield '<b>master_interval</b>: ' + str(uwsgi.getoption(4)) + '<br/>'
    yield '<b>harakiri</b>: ' + str(uwsgi.getoption(5)) + '<br/>'
    yield '<b>cgi_mode</b>: ' + str(uwsgi.get_option(6)) + '<br/>'
    yield '<b>threads</b>: ' + str(uwsgi.get_option(7)) + '<br/>'
    yield '<b>process_reaper</b>: ' + str(uwsgi.get_option(8)) + '<br/>'

    yield '<table border="1">'
    yield '<th>worker id</th><th>pid</th><th>in request</th><th>requests</th><th>running time</th><th>address space</th><th>rss</th>'

    workers = uwsgi.workers();

    yield '<h2>workers</h2>'

    for w in workers:
        #print w
        #print w['running_time']
        if w is not None:
            yield '<tr><td>'+ str(w['id']) +'</td><td>' + str(w['pid']) + '</td><td>' + str(w['pid']) + '</td><td>' + str(w['requests']) + '</td><td>' + str(w['running_time']) + '</td><td>' + str(w['vsz']) + '</td><td>' + str(w['rss']) + '</td></tr>'
            print w

    yield '</table>'

    yield "<h2>PYTHONPATH</h2>"

    yield "<ul>"
    for p in sys.path:
        yield "<li>%s</li>" % p

    yield "</ul>"

    yield "<i>%s</i>" % str(os.uname())
