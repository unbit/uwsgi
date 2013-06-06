"""
simplified test for continulet without checking for partial writes

to enable continulets you only need to call uwsgi_pypy_setup_continulets() soon after startup:

uwsgi --pypy-wsgi-file t/pypy/t_continulet1.py --http-socket :9090 --pypy-home /opt/pypy --pypy-eval "uwsgi_pypy_setup_continulets()" --async 8

"""
import uwsgi
def application(e, sr):
    sr('200 OK', [('Content-Type','text/plain')])

    # call suspend 10 times and yield some value
    for i in range(0,10):
        print i
        uwsgi.suspend()
        yield str(i)

    # connect to a memcached server
    fd = uwsgi.async_connect('127.0.0.1:11211')
    try:
        # start waiting for socket availability (4 seconds max)
        uwsgi.wait_fd_write(fd, 4)
        # suspend execution 'til event
        uwsgi.suspend()
        uwsgi.send(fd, "get /foobar\r\n")
        # now wait for memcached response
        uwsgi.wait_fd_read(fd, 4)
        uwsgi.suspend()
        # read the response
        data = uwsgi.recv(fd, 4096)
        # return to the client
        yield data
    finally:
        uwsgi.close(fd)

    print "sleeping for 3 seconds..."
    uwsgi.async_sleep(3)
    uwsgi.suspend()
    yield "done"
