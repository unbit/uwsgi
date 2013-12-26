import uwsgi
import os
import gc
import sys
from uwsgidecorators import *
print(sys.version)
print(sys.version_info)
if 'set_debug' in gc.__dict__:
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
    print("request finished")

uwsgi.after_req_hook = after_request_hook

@rpc('hello')
def hello_rpc(one, two, three):
    arg0 = one[::-1]
    arg1 = two[::-1]
    arg2 = three[::-1]
    return "!%s-%s-%s!" % (arg1, arg2, arg0)

@signal(17)
def ciao_mondo(signum):
    print("Hello World")

def xsendfile(e, sr):
    sr('200 OK', [('Content-Type', 'image/png'), ('X-Sendfile', os.path.abspath('logo_uWSGI.png'))])
    return ''

def serve_logo(e, sr):
    # use raw facilities (status will not be set...)
    uwsgi.send("%s 200 OK\r\nContent-Type: image/png\r\n\r\n" % e['SERVER_PROTOCOL'])
    uwsgi.sendfile('logo_uWSGI.png')
    return ''

def serve_config(e, sr):
    sr('200 OK', [('Content-Type', 'text/html')])
    for opt in uwsgi.opt.keys():
        yield "<b>%s</b> = %s<br/>" % (opt, uwsgi.opt[opt])

routes = {}
routes['/xsendfile'] = xsendfile
routes['/logo'] = serve_logo
routes['/config'] = serve_config

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

    if env['PATH_INFO'] in routes:
        return routes[env['PATH_INFO']](env, start_response)


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
        apps = '<table border="1"><tr><th>id</th><th>mountpoint</th><th>startup time</th><th>requests</th></tr>'
        for app in w['apps']:
            apps += '<tr><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>' % (app['id'], app['mountpoint'], app['startup_time'], app['requests']) 
        apps += '</table>'
        workers += """
<tr>
<td>%d</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td>
</tr>
        """ % (w['id'], w['pid'], w['status'], w['running_time']/1000, w['avg_rt']/1000, w['tx'], apps)

    output = """
<img src="/logo"/> version %s running on %s (remote user: %s)<br/>
<hr size="1"/>

Configuration<br/>
<iframe src="/config"></iframe><br/>

<br/>
Workers and applications<br/>
<table border="1">
<tr>
<th>wid</th><th>pid</th><th>status</th><th>running time</th><th>average</th><th>tx</th><th>apps</th>
</tr>
%s
</table>

    """ % (uwsgi.version, uwsgi.hostname, env.get('REMOTE_USER','None'), workers)

    start_response('200 OK', [('Content-Type', 'text/html'), ('Content-Length', str(len(output)) )])

    #return bytes(output.encode('latin1'))
    return output





