import uwsgi
print uwsgi.version
print uwsgi.workers()
uwsgi.cache_set('foo', "Hello World from cache")
def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    yield "foobar<br/>"
    yield str(env['wsgi.input'].fileno())
    yield "<h1>Hello World</h1>"
    yield uwsgi.cache_get('foo')
