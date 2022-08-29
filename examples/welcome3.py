import uwsgi
import os

from os.path import abspath, dirname, join

logo_png = abspath(join(dirname(__file__), "../logo_uWSGI.png"))


def xsendfile(e, sr):
    sr(
        "200 OK", [("Content-Type", "image/png"), ("X-Sendfile", logo_png),],
    )
    return b""


def serve_logo(e, sr):
    sr("200 OK", [("Content-Type", "image/png")])
    return uwsgi.sendfile(logo_png)


def serve_config(e, sr):
    sr("200 OK", [("Content-Type", "text/html")])
    for opt in uwsgi.opt.keys():

        def decode_if_bytes(val):
            if isinstance(val, bytes):
                return val.decode("ascii")
            return val

        body = "{opt} = {optvalue}<br/>".format(
            opt=opt.decode("ascii"), optvalue=decode_if_bytes(uwsgi.opt[opt])
        )
        yield bytes(body.encode("ascii"))


routes = {}
routes["/xsendfile"] = xsendfile
routes["/logo"] = serve_logo
routes["/config"] = serve_config


def application(env, start_response):

    if env["PATH_INFO"] in routes:
        return routes[env["PATH_INFO"]](env, start_response)

    start_response("200 OK", [("Content-Type", "text/html")])

    body = """
<img src="/logo"/> version {version}<br/>
<hr size="1"/>

Configuration<br/>
<iframe src="/config"></iframe><br/>

<br/>

    """.format(
        version=uwsgi.version
    )

    return [bytes(body.encode("ascii"))]
