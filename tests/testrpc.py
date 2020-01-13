import uwsgi

def hello():
    pass

def application(env, start_response):
    try:
        uwsgi.register_rpc("A"*300, hello)
        start_response('500 Buffer Overflow', [('Content-Type', 'text/plain')])
    except ValueError:
        start_response('200 OK', [('Content-Type', 'text/plain')])

    return ()
