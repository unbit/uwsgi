

async def asgifoo(scope, receive, send):
    try:
        pprint.pprint("in asgifoo")
        event = await receive()
        pprint.pprint("asgifoo got")
        pprint.pprint(event)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"X-Header", b"Amazing Value"),
                    (b"Content-Type", b"text/plain; charset=UTF-8"),
                ],
            }
        )
        for i in range(32):
            await send(
                {
                    "type": "http.response.body",
                    "body": b"Hello from asgifoo %d\n" % i,
                    "more_body": True,
                }
            )
            await asyncio.sleep(1)
        await send({"type": "http.response.body", "body": b"Goodbye from asgifoo"})
    except:
        # critical debug info
        import traceback

        traceback.print_exc()


import sys


def trace_calls_and_returns(frame, event, arg):
    co = frame.f_code
    func_name = co.co_name
    if func_name == "write":
        # Ignore write() calls from print statements
        return
    line_no = frame.f_lineno
    filename = co.co_filename
    if event == "call":
        print("Call to %s on line %s of %s" % (func_name, line_no, filename))
        return trace_calls_and_returns
    elif event == "return":
        print("%s => %s" % (func_name, arg))
    # else:
    #     print(event)
    return


from starlettetest import app


def application(env, sr):
    """
    Adapt uwsgi + greenlets to asgi + asyncio
    """

    # skip extra request
    if env["PATH_INFO"] == "/favicon.ico":
        sr("200 OK", [("Content-Type", "image/x-icon")])
        return [b""]

    import _uwsgi
    from _uwsgi import ffi, lib

    wsgi_req = _uwsgi.lib.uwsgi.current_wsgi_req()

    environ = {}
    headers = []
    iov = wsgi_req.hvec
    for i in range(0, wsgi_req.var_cnt, 2):
        key, value = (
            ffi.string(ffi.cast("char*", iov[i].iov_base), iov[i].iov_len),
            ffi.string(ffi.cast("char*", iov[i + 1].iov_base), iov[i + 1].iov_len),
        )
        if key.startswith(b"HTTP_"):
            headers.append((key[5:].lower(), value))
        else:
            environ[key.decode("ascii")] = value

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.1"},
        "http_version": environ["SERVER_PROTOCOL"][len("HTTP/") :].decode("utf-8"),
        "method": environ["REQUEST_METHOD"].decode("utf-8"),
        "scheme": environ.get("UWSGI_SCHEME", "http"),
        "path": environ["PATH_INFO"].decode("utf-8"),
        "raw_path": environ["REQUEST_URI"],
        "query_string": environ["QUERY_STRING"],
        "root_path": environ["SCRIPT_NAME"].decode("utf-8"),
        "headers": headers,
        # some references to REMOTE_PORT but not always in environ
        "client": (environ["REMOTE_ADDR"].decode("utf-8"), 0),
        "server": (environ["SERVER_NAME"].decode("utf-8"), environ["SERVER_PORT"]),
    }

    gc = greenlet.getcurrent()

    async def send(event):
        gc.switch(event)
        # do we need to do anything else to avoid pausing asyncio? or to give
        # backpressure to the asgi app by waiting a bit longer?
        # uwsgi probably switches to main greenlet / event loop for us.

    async def receive():
        print("can we rx something?")
        return {"type": "http.request"}

    asyncio.get_event_loop().create_task(app(scope, receive, send))

    while True:
        event = gc.parent.switch()
        print("got", event, "in adapter")
        if event["type"] == "http.response.start":
            # raw uwsgi function accepts bytes
            sr(
                str(event["status"]),
                [
                    [key.decode("latin1"), value.decode("latin1")]
                    for (key, value) in event["headers"]
                ],
            )
        elif event["type"] == "http.response.body":
            yield event["body"]
            if not event.get("more_body"):
                break

