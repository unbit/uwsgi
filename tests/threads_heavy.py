# https://github.com/unbit/uwsgi/pull/2615
# CPU heavy application in multi threaded uWSGI doesn't shutdown gracefully.
#
# $ ./uwsgi \
#     --wsgi-file=threads_heavy.py --master --http-socket=:8000 \
#     --workers=4 --threads=8 --max-requests=20 --min-worker-lifetime=6 -L  \
#     --worker-reload-mercy=20 2>&1 | tee uwsgi.log
#
# $ hey -c 16 -z 3m 'http://127.0.0.1:8000/'
#
# $ grep MERCY uwsgi.log
# Tue Mar 19 14:01:59 2024 - worker 1 (pid: 62113) is taking too much time to die...NO MERCY !!!
# Tue Mar 19 14:02:23 2024 - worker 2 (pid: 62218) is taking too much time to die...NO MERCY !!!
# ...
#
# This was caused by pthread_cancel() is called from non-main thread.

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])
    n = 24
    r = fibonacci(n)
    s = f"F({n}) = {r}"
    return [s.encode()]
