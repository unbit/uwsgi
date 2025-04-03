#!/usr/bin/python3
# uwsgi --plugin python,http --http 0.0.0.0:8000 -w app

from werkzeug.wrappers import Request, Response


def application(env, start_response):
    request = Request(env)
    lines = b""
    while True:
        line = request.stream.readline()
        if not line:
            break;
        lines += line
    response = Response(lines)
    return response(env, start_response)
