from __future__ import print_function
import gc
import io
import os.path
import time

import flask
import flask.helpers


application = flask.Flask(__name__)

FILENAME = os.path.join(os.path.dirname(__file__), "static", "test.txt")
FILENAME2 = os.path.join(os.path.dirname(__file__), "static", "test2.txt")

@application.after_request
def _after(response):
    gc.collect()
    fds = os.listdir("/proc/self/fd")
    print("PY: objects:", len(gc.get_objects()), "fds:", len(fds))
    return response

@application.route("/")
def index():
    return "HELLO\n"

@application.route("/1")
def send_file_1():
    fp = open(FILENAME, "rb")
    return flask.send_file(fp, attachment_filename="test.txt")


@application.route("/2")
def send_file_2():
    bio = io.BytesIO(b"cookie\n")
    return flask.send_file(bio, attachment_filename="test.txt")


@application.route("/3")
def send_file_3():
    """
    What happens if we call the wsgi.file_wrapper twice?

    This should respond with cookie2
    """
    fp = open(FILENAME, "rb")
    flask.send_file(fp, attachment_filename="test.txt")
    fp = open(FILENAME2, "rb")
    return flask.send_file(fp, attachment_filename="test.txt")


@application.route("/4")
def send_file_4():
    """
    Non-filelike object to send_file/wrap_file/wsgi.file_wrapper.

    AttributeError on the call to wsgi.file_wrapper.
    """
    return flask.send_file(object(), attachment_filename="test.txt")


@application.route("/stream1")
def stream1():
    """
    Unrelated to wsgi.file_wrapper, just ensuring the iterator stuff still works.
    """
    def _yield():
        start = time.time()
        for i in range(3):
            time.sleep(0.1)
            yield " {:.2f} cookie".format(time.time() - start).encode("utf-8")
        yield b"\n"
    return flask.Response(_yield(), mimetype="text/plain")


@application.route("/stream2")
def stream2():
    """
    Yielding the result of a wrap_file call with a file object.

    gunicorn / werkzeug do not support this as it's not required.
    """
    fp = open(FILENAME, "rb")
    resp = flask.helpers.wrap_file(flask.request.environ, fp)
    print("PY: resp after return", hex(id(resp)))

    def _yield():
        print("PY: _yield() run", hex(id(resp)), repr(resp))
        yield resp
    return flask.Response(_yield())


@application.route("/stream3")
def stream3():
    """
    Yielding the result of a wrap_file call with a BytesIO object.

    gunicorn / werkzeug do not support this as it's not required.
    """
    bio = io.BytesIO(b"cookie\n")
    resp = flask.helpers.wrap_file(flask.request.environ, bio)

    def _yield():
        yield resp
    return flask.Response(_yield())


@application.route("/stream4")
def stream4():
    """
    werkzeug logs: AssertionError: applications must write bytes
    gunicorn logs: TypeError: <Response streamed [200 OK]> is not a byte
    uwsgi didn't log, should now..
    """
    fp = open(FILENAME, "rb")
    resp = flask.send_file(fp, attachment_filename="test.txt")
    print("PY: resp after return", hex(id(resp)))

    def _yield():
        print("PY: _yield() run", hex(id(resp)), repr(resp))
        yield resp
    return flask.Response(_yield(), direct_passthrough=True)
