PAYLOAD = b"0123456789abcdef" * 4096


def application(environ, start_response):
    path = environ["PATH_INFO"]
    if path == "/no-body":
        start_response("204 No Content", [])
        return []
    start_response("200 OK", [("Content-Type", "text/plain")])
    if path == "/empty-chunk":
        return [b""]
    if path == "/leading-empty-chunk":
        return [b"", PAYLOAD]
    return [PAYLOAD]
