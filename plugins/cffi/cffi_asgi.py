"""
event-loop independent ASGI functions
"""

from _uwsgi import ffi, lib


def asgi_start_response(wsgi_req, status, headers):
    status = b"%d" % status
    lib.uwsgi_response_prepare_headers(wsgi_req, ffi.new("char[]", status), len(status))
    for (header, value) in headers:
        lib.uwsgi_response_add_header(
            wsgi_req,
            ffi.new("char[]", header),
            len(header),
            ffi.new("char[]", value),
            len(value),
        )


def asgi_scope_http(wsgi_req):
    """
    Create the ASGI scope for a http or websockets connection.
    """
    environ = {}
    headers = []
    iov = wsgi_req.hvec
    for i in range(0, wsgi_req.var_cnt, 2):
        key, value = (
            ffi.string(ffi.cast("char*", iov[i].iov_base), iov[i].iov_len),
            ffi.string(ffi.cast("char*", iov[i + 1].iov_base), iov[i + 1].iov_len),
        )
        if key.startswith(b"HTTP_"):
            # replace cgi-style _ with http-style -
            headers.append((key[5:].lower().replace(b"_", b"-"), value))
        else:
            environ[key.decode("ascii")] = value

    REMOTE_PORT = 0
    if "REMOTE_PORT" in environ:
        REMOTE_PORT = int(environ["REMOTE_PORT"])
    SERVER_PORT = 0
    if "SERVER_PORT" in environ:
        SERVER_PORT = int(environ["SERVER_PORT"])

    scope = {
        "type": "http",
        "asgi": {"spec_version": "2.1"},
        "http_version": environ["SERVER_PROTOCOL"][len("HTTP/") :].decode("utf-8"),
        "method": environ["REQUEST_METHOD"].decode("utf-8"),
        "scheme": "http",
        "path": environ["PATH_INFO"].decode("utf-8"),
        "raw_path": environ["REQUEST_URI"],
        "query_string": environ["QUERY_STRING"],
        "root_path": environ["SCRIPT_NAME"].decode("utf-8"),
        "headers": headers,
        # some references to REMOTE_PORT but not always in environ
        "client": (environ["REMOTE_ADDR"].decode("utf-8"), REMOTE_PORT),
        "server": (environ["SERVER_NAME"].decode("utf-8"), SERVER_PORT),
        "extensions": {"environ": environ},
    }

    if environ.get("HTTPS") in (b"on",):
        scope["scheme"] = "https"

    if wsgi_req.http_sec_websocket_key != ffi.NULL:
        scope["type"] = "websocket"
        if scope["scheme"] == "https":
            scope["scheme"] = "wss"
        else:
            scope["scheme"] = "ws"

    return scope


def websocket_recv_nb(wsgi_req):
    """
    uwsgi.websocket_recv_nb()
    """
    ub = lib.uwsgi_websocket_recv_nb(wsgi_req)
    if ub == ffi.NULL:
        raise IOError("unable to receive websocket message")
    ret = ffi.buffer(ub.buf, ub.pos)[:]
    lib.uwsgi_buffer_destroy(ub)
    return ret


def websocket_handler(wsgi_req, _send, _ready):
    """
    Return (send, receive) for ASGI websocket.

    wsgi_req: the request
    _send: await _send(event)
    _ready: await next message
    """

    closed = False

    async def receiver():
        nonlocal closed

        yield {"type": "websocket.connect"}

        msg = None
        while True:
            try:
                print("rx, closed=", closed)
                msg = websocket_recv_nb(wsgi_req)
            except IOError:
                closed = True
                await _send({"type": "websocket.close"})
                yield {
                    "type": "websocket.disconnect",
                    "code": 1000,
                }  # todo lookup code
                # don't raise, keep receivin' ?
                continue  # or return?
            if msg:
                # check wsgi_req->websocket_opcode for text / binary
                value = {"type": "websocket.receive"}
                # *  %x0 denotes a continuation frame
                # *  %x1 denotes a text frame
                # *  %x2 denotes a binary frame
                opcode = wsgi_req.websocket_opcode
                if opcode == 1:
                    value["text"] = msg.decode("utf-8")
                elif opcode == 2:
                    value["bytes"] = msg
                else:
                    print("surprise opcode", opcode)
                yield value
            else:
                print("no msg", wsgi_req.websocket_opcode)
                await _ready()

    receive = receiver().__anext__

    async def send(event):
        nonlocal closed
        print("ws send", event)
        if closed:
            print("ignore send on closed ws")

        elif event["type"] == "websocket.accept":
            if (
                lib.uwsgi_websocket_handshake(
                    wsgi_req, ffi.NULL, 0, ffi.NULL, 0, ffi.NULL, 0
                )
                < 0
            ):
                closed = True
                await _send({"type": "websocket.close"})
                raise IOError("unable to send websocket handshake")

        elif event["type"] == "websocket.send":
            # ok to call during any part of app?
            if "bytes" in event:
                msg = event["bytes"]
                websocket_send = lib.uwsgi_websocket_send_binary
            else:
                msg = event["text"].encode("utf-8")
                websocket_send = lib.uwsgi_websocket_send
            if websocket_send(wsgi_req, ffi.new("char[]", msg), len(msg)) < 0:
                closed = True
                await _send({"type": "websocket.close"})
                raise IOError("unable to send websocket message")

        elif event["type"] == "websocket.close":
            print("asked to close in send")
            closed = True
            await _send(event)

    return (send, receive)
