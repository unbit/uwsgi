from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


async def homepage(request):
    return JSONResponse({"hello": "world"})


app = Starlette(debug=True, routes=[Route("/", homepage)])

import sys


UNINTERESTING_FUNCS = set(("asgi_scope_http",))


def trace_calls_and_returns(frame, event, arg):
    co = frame.f_code
    func_name = co.co_name
    if func_name == "write":
        # Ignore write() calls from print statements
        return
    line_no = frame.f_lineno
    filename = co.co_filename
    if not filename.startswith("/Users/daniel/prog/uwsgi/plugins/cffi/"):
        return
    if event == "call":
        print("Call to %s on line %s of %s" % (func_name, line_no, filename))
        return trace_calls_and_returns
    elif event == "return":
        print("%s => %s" % (func_name, arg))
    elif event == "line" and func_name not in UNINTERESTING_FUNCS:
        print("%s:%s of %s" % (func_name, line_no, filename))
    # else:
    #     print(event)
    return


# sys.settrace(trace_calls_and_returns)
