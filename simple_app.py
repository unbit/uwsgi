import uwsgi
import os

print("!!! uWSGI version:", uwsgi.version)

def ciao():
    print("modifica su /tmp")

def ciao2():
    print("nuovo uwsgi_server")
    print os.getpid()

counter = 0

#if uwsgi.load_plugin(0, 'plugins/example/example_plugin.so', 'ciao'):
#    print "example plugin loaded"
#else:
#    print "unable to load example plugin"

#uwsgi.event_add(uwsgi.EVENT_FILE, "/tmp", ciao)
#uwsgi.event_add(uwsgi.EVENT_DNSSD, "_uwsgi._tcp", ciao2)
#uwsgi.event_add(uwsgi.EVENT_TIMER, 1000, ciao2)

uwsgi.post_fork_hook = ciao2

def application(env, start_response):

    global counter


    #print(env)
    start_response('200 Ok', [('Content-type', 'text/plain')])
    yield "hello world"
    yield "hello world2"

    for i in range(1,1000):
        yield str(i)

    yield "\n"

    yield str(counter)
    counter += 1
