import uwsgi

from six.moves import reload_module
import time
import sys
import os

sys.path.insert(0, '/opt/apps')

os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'

#import django.core.handlers.wsgi

#uwsgi.load_plugin(0, "plugins/example/example_plugin.so", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa")

from threading import Thread


class testthread(Thread):
    def run(self):
        while 1:
            time.sleep(2)
            print("i am a terrible python thread of the uWSGI master process", uwsgi.applications)


tthread = testthread()

tthread.start()

p = "serena"

#while 1:
#print("MARSHALLED OUT: ",uwsgi.send_uwsgi_message("127.0.0.1", 3033, 33, 17, {'prodotto':p, 'tempo': time.time(), 'pippo':'pluto', 'topolino':'paperino', 'callable':4+1, 'nullo': None, 'embedded': {'a':1} }, 17))


def mako(filename, vars):
    return uwsgi.send_uwsgi_message("127.0.0.1", 3033, 33, 17, (filename, vars), 17)

#print(uwsgi.send_uwsgi_message("127.0.0.1", 3033, 33, 17, ('makotest.txt', {'whattimeisit':time.time(), 'roberta':'serena'}), 17))


def myspooler(env):
    print(env)
    for i in range(1, 100):
        uwsgi.sharedarea_inclong(100)
        # time.sleep(1)

uwsgi.spooler = myspooler

#print("SPOOLER: ", uwsgi.send_to_spooler({'TESTKEY':'TESTVALUE', 'APPNAME':'uWSGI'}))


def helloworld():
    return 'Hello World'


def increment():
    return "Shared counter is %d\n" % uwsgi.sharedarea_inclong(100)


def force_harakiri():
    time.sleep(60)


def application(env, start_response):
    print(env)
    start_response('200 OK', [('Content-Type', 'text/plain')])
    yield {
        '/': helloworld,
        '/sleep': force_harakiri,
        '/counter': increment,
        '/uwsgi/': helloworld
    }[env['PATH_INFO']]()

    print(env)


def gomako():
    from mako.template import Template
    uwsgi.start_response('200 OK', [('Content-Type', 'text/html')])
    yield Template("hello ${data}!").render(data="world")


def goxml():
    import xml.dom.minidom
    doc = xml.dom.minidom.Document()
    foo = doc.createElement("foo")
    doc.appendChild(foo)
    uwsgi.start_response('200 OK', [('Content-Type', 'text/xml')])
    return doc.toxml()


def djangohomepage():
    from django.template import Template, Context
    uwsgi.start_response('200 OK', [('Content-Type', 'text/html')])
    t = Template("My name is {{ my_name }}.")
    c = Context({"my_name": "Serena"})
    print(t, c)
    a = t.render(c)
    print("ciao", a)
    yield str(a)


def reload(env, start_response):

    start_response('200 OK', [('Content-Type', 'text/html')])

    #uwsgi.sorry_i_need_to_block()
    #time.sleep(1)

    #uwsgi.reload()

#    print(str(uwsgi.masterpid()) + "\n")

#    print("i am python")
    #yo()

#    yield "python"

    #print 4/0

#    yield str(uwsgi.masterpid())

    #print(uwsgi.pippo)

    #print 4/0
#    try:
#        print 4/0
#
#        print uwsgi.pippo
#    except Exception:
#        print "bah"

#    print("ok")

#    yield 4/0

    yield '<h1>uWSGI status ('+env['SCRIPT_NAME']+')</h1>'
    yield 'masterpid: <b>' + str(uwsgi.masterpid()) + '</b><br/>'

    yield 'started on: <b>' + time.ctime(uwsgi.started_on) + '</b><br/>'

    yield 'buffer size: <b>' + str(uwsgi.buffer_size) + '</b><br/>'

    yield 'total_requests: <b>' + str(uwsgi.total_requests()) + '</b><br/>'

    yield 'workers: <b>' + str(uwsgi.numproc) + '</b><br/>'

    yield '<table border="1">'
    yield '<th>worker id</th><th>pid</th><th>in request</th><th>requests</th><th>running time</th><th>address space</th><th>rss</th>'

    workers = uwsgi.workers()

    yield '<h2>workers</h2>'

    for w in workers:
        #print(w)
        #print(w['running_time'])
        if w is not None:
            yield '<tr><td>' + str(w['id']) + '</td><td>' + str(w['pid']) + '</td><td>' + str(w['pid']) + '</td><td>' + str(w['requests']) + '</td><td>' + str(w['running_time']) + '</td><td>' + str(w['vsz']) + '</td><td>' + str(w['rss']) + '</td></tr>'
            print(w)

    yield '</table>'

    #yield out
    #print("FATTOfattoFATTO")


def remotemako(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    clusters = (
        ('192.168.173.5', 3431, [0, 3000]),
        ('192.168.173.5', 3432, [3001, 6000]),
        ('192.168.173.5', 3433, [6001, 9000]),
        ('192.168.173.5', 3434, [9001, 12000]),
        ('192.168.173.5', 3435, [12001, 15000])
    )
    print(clusters)
    all_values = uwsgi.send_multi_uwsgi_message(clusters, 33, 17, 40)
    print(all_values)
    return mako('makotest.txt', {
        'whattimeisit': time.time(),
        'roberta': 'serena',
        'cluster_values': all_values
    })


uwsgi.fastfuncs.insert(10, gomako)
uwsgi.fastfuncs.insert(11, goxml)
uwsgi.fastfuncs.insert(17, djangohomepage)

#djangoapp = django.core.handlers.wsgi.WSGIHandler()

#applications = { '/':django.core.handlers.wsgi.WSGIHandler() }
uwsgi.applications = {
    '/': reload,
    '/pippo': reload
}

print(uwsgi.applications)
print(uwsgi.applist)
