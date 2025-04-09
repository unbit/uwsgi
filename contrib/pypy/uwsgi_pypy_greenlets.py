"""
Greenlets support

simply --pypy-exec this file to enable PyPy's greenlet mode

Example:

uwsgi --http-socket :9090 --pypy-home /opt/pypy --pypy-wsgi werkzeug.testapp:test_app --pypy-exec contrib/pypy/uwsgi_pypy_greenlets.py --async 8
"""

import greenlet

uwsgi_pypy_greenlets = {}


def uwsgi_pypy_greenlet_wrapper():
    lib.async_schedule_to_req_green()


@ffi.callback("void()")
def uwsgi_pypy_greenlet_schedule():
    id = lib.uwsgi.wsgi_req.async_id
    modifier1 = lib.uwsgi.wsgi_req.uh.modifier1

    # generate a new greenlet
    if not lib.uwsgi.wsgi_req.suspended:
        uwsgi_pypy_greenlets[id] = greenlet.greenlet(uwsgi_pypy_greenlet_wrapper)
        lib.uwsgi.wsgi_req.suspended = 1

    # this is called in the main stack
    if lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(ffi.NULL)

    # let's switch
    uwsgi_pypy_greenlets[id].switch()

    # back to the main stack
    if lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(ffi.NULL)


@ffi.callback("void(struct wsgi_request *)")
def uwsgi_pypy_greenlet_switch(wsgi_req):
    wsgi_req.async_id
    modifier1 = wsgi_req.uh.modifier1

    # this is called in the current greenlet
    if lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(wsgi_req)

    uwsgi_pypy_main_greenlet.switch()

    # back to the greenlet
    if lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(wsgi_req)

    # update current running greenlet
    lib.uwsgi.wsgi_req = wsgi_req

if lib.uwsgi.async < 1:
    raise Exception("pypy greenlets require async mode !!!")
lib.uwsgi.schedule_to_main = uwsgi_pypy_greenlet_switch
lib.uwsgi.schedule_to_req = uwsgi_pypy_greenlet_schedule
uwsgi_pypy_main_greenlet = greenlet.getcurrent()
