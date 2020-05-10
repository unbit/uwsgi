import sys
import pprint
import uwsgi

def application(env, start_response):
    start_response("200 OK", [("Content-Type", "text/html")])
    results = [
        b"<pre>",
        "masterpid: %s\n" % uwsgi.masterpid(),
        "worker id: %s\n" % uwsgi.worker_id(),
        "request id: %s\n" % uwsgi.request_id(),
        b"Hello World (regular Python) ",
        sys.executable.encode("utf-8"),
        b" ",
        pprint.pformat(env).encode("utf-8"),
        b"</pre>"
    ]

    for result in results:
        if isinstance(result, str):
            result = result.encode('utf-8')
        yield result