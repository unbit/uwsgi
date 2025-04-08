"""
safer test for continulet with partial writes check

to enable continulets you only need to call uwsgi_pypy_setup_continulets() soon after startup:

uwsgi --pypy-wsgi-file t/pypy/t_continulet2.py --http-socket :9090 --pypy-home /opt/pypy --pypy-eval "uwsgi_pypy_setup_continulets()" --async 8

"""
import uwsgi


def application(e, sr):
    sr('200 OK', [('Content-Type', 'text/plain')])

    # suspend 10 times and yield a value
    for i in range(1, 10):
        print(i)
        uwsgi.suspend()
        yield str(i)

    # connect to a memcached server
    fd = uwsgi.async_connect('127.0.0.1:11211')
    try:
        command = "get /foobar\r\n"
        remains = len(command)
        while remains > 0:
            # start waiting for socket availability (4 seconds max)
            uwsgi.wait_fd_write(fd, 4)
            # suspend execution 'til event
            uwsgi.suspend()
            pos = len(command) - remains
            written = uwsgi.send(fd, command[pos:])
            remains -= written

        # now wait for memcached response
        uwsgi.wait_fd_read(fd, 4)
        uwsgi.suspend()
        # read a chunk of data
        data = uwsgi.recv(fd, 4096)
        # .. and yield it
        yield data
    finally:
        # always ensure sockets are closed
        uwsgi.close(fd)

    print("sleeping for 3 seconds...")
    uwsgi.async_sleep(3)
    uwsgi.suspend()
    yield "done"
