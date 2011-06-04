import uwsgi


def serve_logo(e, sr):
    sr('200 OK', [('Content-Type', 'image/png')])
    return uwsgi.sendfile('logo_uWSGI.png')

def serve_options(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in xrange(0,256):
        yield "%d = %d<br/>" % (opt, uwsgi.get_option(opt))

def serve_config(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in uwsgi.opt.keys():
        yield "%s = %s<br/>" % (opt, uwsgi.opt[opt])

routes = {}
routes['/logo'] = serve_logo
routes['/config'] = serve_config
routes['/options'] = serve_options

def application(env, start_response):

    if routes.has_key(env['PATH_INFO']):
        return routes[env['PATH_INFO']](env, start_response)

    start_response('200 OK', [('Content-Type', 'text/html')])

    return """
<img src="/logo"/> version %s<br/>
<hr size="1"/>

Configuration<br/>
<iframe src="/config"></iframe><br/>

<br/>

Dynamic options<br/>
<iframe src="/options"></iframe><br/>

    """ % (uwsgi.version)






