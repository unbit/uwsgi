"""
Regression test for #2056 - uwsgi.workers() leaking objects.
"""
import uwsgi
import gc


def application(env, start_response):
    gc.collect()
    start_objs = len(gc.get_objects())

    for i in range(200):
        workers = uwsgi.workers()
        assert workers, "none/empty uwsgi.workers() - " + repr(workers)
        for w in workers:
            assert w["apps"], "none/empty apps in worker dict: " + repr(w)

    gc.collect()
    end_objs = len(gc.get_objects())
    diff_objs = end_objs - start_objs

    # Sometimes there is a spurious diff of 4 objects or so.
    if diff_objs > 10:
        start_response('500 Leaking', [('Content-Type', 'text/plain')])
        yield "Leaking objects...\n".encode("utf-8")
    else:
        start_response('200 OK', [('Content-Type', 'text/plain')])

    yield "{} {} {}\n".format(start_objs, end_objs, diff_objs).encode("utf-8")
