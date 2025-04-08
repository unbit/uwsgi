def application(environ, start_response):
    print(environ)
    start_response('200 OK', [])
    if not environ['wsgi.input_terminated']:
        return []
#    print(environ['wsgi.input'].read())
    data = environ['wsgi.input'].read(2)
    print(data)
    data = environ['wsgi.input'].read(2)
    print(data)
    data = environ['wsgi.input'].read(2)
    print(data)
    data = environ['wsgi.input'].read(6)
    print(data)
    print(environ['wsgi.input'].read())
    return [data]
