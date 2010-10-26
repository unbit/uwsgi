
def mygen(uri):
    for i in xrange(1,100):
        yield "ciao %s<br/>" % uri


def application(env, start_response = None):
    return '200 OK',  [('Content-Type', 'text/html')], "<h1>This is the fastest homepage of the world !!!</h1>"
    #return '200 OK',  [('Content-Type', 'text/html')], mygen(env['PATH_INFO'])
