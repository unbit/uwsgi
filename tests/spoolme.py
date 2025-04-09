import uwsgi
import time


def slow_task(args):
    time.sleep(10)
    return uwsgi.SPOOL_OK

uwsgi.spooler = slow_task


def application(env, start_response):

    name = uwsgi.spool({
        'Hello': 'World',
        'I am a': 'long running task'
    })
    print("spooled as %s" % name)

    start_response('200 Ok', [
        ('Content-Type', 'text/plain'),
        ('uWSGI-Status', 'spooled'),
    ])

    return "task spooled"
