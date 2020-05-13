"""
cffi init, not baked into .so
"""

from cffi_plugin import ffi, lib


@ffi.def_extern()
def uwsgi_cffi_after_request(wsgi_req):
    print("overridden callback!")
    lib.log_request(wsgi_req)


import cffi_asyncio


"""
Continulets support
"""

# this is the dictionary of continulets (one per-core)
uwsgi_pypy_continulets = {}


def uwsgi_pypy_continulet_wrapper(cont):
    lib.async_schedule_to_req_green()


@ffi.def_extern()
def uwsgi_pypy_continulet_schedule():
    id = lib.uwsgi.wsgi_req.async_id
    modifier1 = lib.uwsgi.wsgi_req.uh.modifier1

    # generate a new continulet
    if not lib.uwsgi.wsgi_req.suspended:
        from _continuation import continulet

        uwsgi_pypy_continulets[id] = continulet(uwsgi_pypy_continulet_wrapper)
        lib.uwsgi.wsgi_req.suspended = 1

    # this is called in the main stack
    if lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(ffi.NULL)

    # let's switch
    uwsgi_pypy_continulets[id].switch()

    # back to the main stack
    if lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(ffi.NULL)


@ffi.def_extern()
def uwsgi_pypy_continulet_switch(wsgi_req):
    id = wsgi_req.async_id
    modifier1 = wsgi_req.uh.modifier1

    # this is called in the current continulet
    if lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(wsgi_req)

    uwsgi_pypy_continulets[id].switch()

    # back to the continulet
    if lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(wsgi_req)

    # update current running continulet
    lib.uwsgi.wsgi_req = wsgi_req


def uwsgi_pypy_setup_continulets():
    if getattr(lib.uwsgi, "async") < 1:  # keyword
        raise Exception("pypy continulets require async mode !!!")
    lib.uwsgi.schedule_to_main = uwsgi_pypy_continulet_switch
    lib.uwsgi.schedule_to_req = uwsgi_pypy_continulet_schedule
    print("*** PyPy Continulets engine loaded ***")
