import uwsgi
import os
import gc
import sys
from uwsgidecorators import *
gc.set_debug(gc.DEBUG_SAVEALL)

print(os.environ)
print(sys.modules)
print(sys.argv)

try:
    if sys.argv[1] == 'debug':
        DEBUG = True
    else:
        raise
except:
    DEBUG = False


def after_request_hook():
    print "request finished"

uwsgi.after_req_hook = after_request_hook

def xsendfile(e, sr):
    sr('200 OK', [('Content-Type', 'image/png'), ('X-Sendfile', os.path.abspath('logo_uWSGI.png'))])
    return ''

def serve_logo(e, sr):
    sr('200 OK', [('Content-Type', 'image/png')])
    return uwsgi.sendfile('logo_uWSGI.png')

def serve_options(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in xrange(0,256):
        yield "<b>%d</b> = %d<br/>" % (opt, uwsgi.get_option(opt))

def serve_config(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in uwsgi.opt.keys():
        yield "<b>%s</b> = %s<br/>" % (opt, uwsgi.opt[opt])

routes = {}
routes['/xsendfile'] = xsendfile
routes['/logo'] = serve_logo
routes['/config'] = serve_config
routes['/options'] = serve_options

@postfork
def setprocname():
    if uwsgi.worker_id() > 0:
        uwsgi.setprocname("i am the worker %d" % uwsgi.worker_id())

def application(env, start_response):

    try:
        uwsgi.mule_msg(env['REQUEST_URI'], 1)
    except:
        pass

    req = uwsgi.workers()[uwsgi.worker_id()-1]['requests']

    uwsgi.setprocname("worker %d managed %d requests" % (uwsgi.worker_id(), req))

    try:
        gc.collect(2)
    except:
        pass
    if DEBUG:
        print(env['wsgi.input'].fileno())

    if routes.has_key(env['PATH_INFO']):
        return routes[env['PATH_INFO']](env, start_response)

    start_response('200 OK', [('Content-Type', 'text/html')])

    if DEBUG:
        print(env['wsgi.input'].fileno())

    try:
        gc.collect(2)
    except:
        pass

    if DEBUG:
        print(len(gc.get_objects()))

    workers = ''
    for w in uwsgi.workers():
        apps = '<table border="1"><tr><th>id</th><th>mountpoint</th><th>requests</th></tr>'
        for app in w['apps']:
            apps += '<tr><td>%d</td><td>%s</td><td>%d</td></tr>' % (app['id'], app['mountpoint'], app['requests']) 
        apps += '</table>'
        workers += """
<tr>
<td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td>
</tr>
        """ % (w['id'], w['pid'], w['status'], w['running_time']/1000, w['avg_rt']/1000, w['tx'], apps)

    return """
<img src="/logo"/> version %s running on %s<br/>
<hr size="1"/>

Configuration<br/>
<iframe src="/config"></iframe><br/>

<br/>

Dynamic options<br/>
<iframe src="/options"></iframe><br/>

<br/>
Workers and applications<br/>
<table border="1">
<tr>
<th>wid</th><th>pid</th><th>status</th><th>running time</th><th>average</th><th>tx</th><th>apps</th>
</tr>
%s
</table>

    """ % (uwsgi.version, uwsgi.hostname, workers)






