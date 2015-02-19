# uwsgi --route-run remheader:Content-Length --route-run forcecl: --wsgi-file t/python/forcecl.py --http-socket :9090
def application(e, sr):
    sr('200 OK', [('Content-Length', '1'), ('Content-Length', '2')])
    return ['xxx']
