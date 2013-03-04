import uwsgi

sleepvalue = 5

def application(env, start_response):
    start_response('200 Ok', [('Content-type', 'text/html')])
    yield uwsgi.async_sleep(sleepvalue)
    #print "TIMEOUT: ", env['x-wsgiorg.fdevent.timeout']
    yield "<h1>Hello World after %d seconds</h1>" % sleepvalue
