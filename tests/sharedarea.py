import uwsgi

uwsgi.sharedarea_writelong(173, 30)


def application(e, sr):

    sr('200 Ok', [('Content-Type', 'text/html')])

    uwsgi.sharedarea_write(17, e['REQUEST_URI'])

    uwsgi.sharedarea_inclong(173)
    uwsgi.sharedarea_inclong(173, 17)

    yield uwsgi.sharedarea_read(17, len(e['REQUEST_URI']))
    yield "<br/>"
    yield str(uwsgi.sharedarea_readlong(173))
