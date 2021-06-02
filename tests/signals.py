import uwsgi


def hello_signal(num, payload):
    print("i am the signal %d" % num)


def hello_signal2(num, payload):
    print("i am the signal %d with payload: %s" % (num, payload))


def hello_file(num, filename):
    print("file %s has been modified !!!" % filename)


def hello_timer(num, secs):
    print("%s seconds elapsed" % secs)

# uwsgi.register_signal(30, uwsgi.SIGNAL_KIND_WORKER, hello_signal)
uwsgi.register_signal(30, "workers", hello_signal)
uwsgi.register_signal(22, "worker", hello_signal2, "*** PAYLOAD FOO ***")

uwsgi.register_file_monitor(3, "/tmp", "workers", hello_file)
uwsgi.register_timer(26, 2, "worker", hello_timer)
uwsgi.register_timer(17, 4, "worker2", hello_timer)
uwsgi.register_timer(5, 8, "worker3", hello_timer)


def application(env, start_response):

    start_response('200 Ok', [('Content-Type', 'text/html')])

    # this will send a signal to the master that will report it to the first available worker
    uwsgi.signal(30)
    uwsgi.signal(22)

    return "signals sent to workers"
