import uwsgi
import time


def application(env, start_response):
    sleepvalue = 5
    if 'QUERY_STRING' in env:
        if env['QUERY_STRING'] != '':
            sleepvalue = int(env['QUERY_STRING'])
        start_response('200 Ok', [('Content-type', 'text/html')])
    start_at = time.time()
    uwsgi.green_sleep(sleepvalue)
    # print("TIMEOUT: ", env['x-wsgiorg.fdevent.timeout'])
    yield "<h1>Hello World after %s seconds</h1>" % str(time.time() - start_at)
