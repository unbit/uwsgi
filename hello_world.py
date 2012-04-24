import uwsgi
if uwsgi.loop == 'gevent':
    import gevent

print uwsgi.version
print uwsgi.workers()
try:
    uwsgi.cache_set('foo', "Hello World from cache")
except:
    pass
def application(env, start_response):
    if uwsgi.loop == 'gevent':
        gevent.sleep()
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "foobar<br/>"
    if uwsgi.loop == 'gevent':
        gevent.sleep(3)
    yield str(env['wsgi.input'].fileno())
    yield "<h1>Hello World</h1>"
    try:
        yield uwsgi.cache_get('foo')
    except:
        pass
