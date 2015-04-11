import uwsgi
import time


def application(env, start_response):
    counter = 0
    start_response('200 OK', [('Content-Type', 'text/html')])
    start_time = time.time()
    for i in range(1, 100000):
        uwsgi.suspend()
        # print every 100
        if i % 100 == 0:
            yield "<h1>%d</h1>\n" % i
        counter = counter + i

    yield "<h1>%d cycles after %d</h1>\n" % (counter, time.time() - start_time)
