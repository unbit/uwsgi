import sys
import pprint


def application(env, start_response):
    start_response("200 OK", [("Content-Type", "text/html")])
    return [
        b"Hello World (regular Python) ",
        sys.executable.encode("utf-8"),
        b" ",
        pprint.pformat(env).encode("utf-8"),
    ]
