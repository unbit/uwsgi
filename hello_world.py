import uwsgi
uwsgi.cache_set('/', "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nHello World from cache")
def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    return "<h1>Hello World</h1>"
