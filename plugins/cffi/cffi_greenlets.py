"""
Greenlets and continulets support; pick one.
"""

from _uwsgi import ffi, lib

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
    lib.uwsgi.schedule_to_main = lib.uwsgi_pypy_continulet_switch
    lib.uwsgi.schedule_to_req = lib.uwsgi_pypy_continulet_schedule
    print("*** PyPy Continulets engine loaded ***")


# Greenlets support
# May prefer to continulets.
# Built in to pypy (built on top of continulets)

uwsgi_pypy_greenlets = {}


def uwsgi_pypy_greenlet_wrapper():
    lib.async_schedule_to_req_green()


@ffi.def_extern()
def uwsgi_pypy_greenlet_current_wsgi_req():
    try:
        return greenlet.getcurrent().uwsgi_wsgi_req
    except AttributeError:
        lib.uwsgi_log(b"[BUG] current_wsgi_req NOT FOUND!!!\n")
        return lib.uwsgi.wsgi_req  # called early once?
    return ffi.NULL


def not_cffi(modifier1):
    """
    Is the request related to our plugin?
    """
    return ffi.string(lib.uwsgi.p[modifier1].name) != b"cffi"


@ffi.def_extern()
def uwsgi_pypy_greenlet_schedule_to_req():
    id = lib.uwsgi.wsgi_req.async_id
    modifier1 = lib.uwsgi.wsgi_req.uh.modifier1

    # generate a new greenlet
    if not lib.uwsgi.wsgi_req.suspended:
        uwsgi_pypy_greenlets[id] = greenlet.greenlet(uwsgi_pypy_greenlet_wrapper)
        uwsgi_pypy_greenlets[id].uwsgi_wsgi_req = lib.uwsgi.wsgi_req
        lib.uwsgi.wsgi_req.suspended = 1

    # this is called in the main stack
    if not_cffi(modifier1) and lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(ffi.NULL)

    # let's switch
    uwsgi_pypy_greenlets[id].switch()

    # back to the main stack
    if not_cffi(modifier1) and lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(ffi.NULL)


@ffi.def_extern()
def uwsgi_pypy_greenlet_schedule_to_main(wsgi_req):
    wsgi_req.async_id
    modifier1 = wsgi_req.uh.modifier1

    # this is called in the current greenlet
    if not_cffi(modifier1) and lib.uwsgi.p[modifier1].suspend:
        lib.uwsgi.p[modifier1].suspend(wsgi_req)

    uwsgi_pypy_main_greenlet.switch()

    # back to the greenlet
    if not_cffi(modifier1) and lib.uwsgi.p[modifier1].resume:
        lib.uwsgi.p[modifier1].resume(wsgi_req)

    # update current running greenlet
    lib.uwsgi.wsgi_req = wsgi_req


def uwsgi_cffi_setup_greenlets():
    global greenlet, uwsgi_pypy_main_greenlet
    import greenlet

    if getattr(lib.uwsgi, "async") < 1:
        raise Exception("pypy greenlets require async mode !!!")

    lib.uwsgi.schedule_to_main = lib.uwsgi_pypy_greenlet_schedule_to_main
    lib.uwsgi.schedule_to_req = lib.uwsgi_pypy_greenlet_schedule_to_req
    lib.uwsgi.current_wsgi_req = lib.uwsgi_pypy_greenlet_current_wsgi_req
    uwsgi_pypy_main_greenlet = greenlet.getcurrent()
