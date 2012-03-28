import uwsgi
if uwsgi.loop == 'gevent':
    import gevent

print uwsgi.version
print uwsgi.workers()
uwsgi.cache_set('foo', "Hello World from cache")
def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "foobar<br/>"
    if uwsgi.loop == 'gevent':
        gevent.sleep(10)
    yield str(env['wsgi.input'].fileno())
    yield "<h1>Hello World</h1>"
    yield uwsgi.cache_get('foo')
