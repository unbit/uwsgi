import uwsgi
import os

def xsendfile(e, sr):
    sr('200 OK', [('Content-Type', 'image/png'), ('X-Sendfile', os.path.abspath('logo_uWSGI.png'))])
    return b''

def serve_logo(e, sr):
    sr('200 OK', [('Content-Type', 'image/png')])
    return uwsgi.sendfile('logo_uWSGI.png')

def serve_config(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in uwsgi.opt.keys():
        body = "{opt} = {optvalue}<br/>".format(opt=opt, optvalue=uwsgi.opt[opt].decode('ascii'))
        yield bytes(body.encode('ascii'))

routes = {}
routes['/xsendfile'] = xsendfile
routes['/logo'] = serve_logo
routes['/config'] = serve_config

def application(env, start_response):

    if env['PATH_INFO'] in routes:
        return routes[env['PATH_INFO']](env, start_response)

    start_response('200 OK', [('Content-Type', 'text/html')])

    body = """
<img src="/logo"/> version {version}<br/>
<hr size="1"/>

Configuration<br/>
<iframe src="/config"></iframe><br/>

<br/>

    """.format(version=uwsgi.version.decode('ascii'))

    return bytes(body.encode('ascii'))






