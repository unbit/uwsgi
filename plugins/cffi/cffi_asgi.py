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
