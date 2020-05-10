"""
Implement the uwsgi module.
"""

from cffi_plugin import ffi, lib

# version = ... # parse from uwsgi_get_cflags()?
hostname = ffi.string(lib.uwsgi.hostname)

def masterpid():
    if lib.uwsgi.master_process:
        return lib.uwsgi.workers[0].pid
    return 0

def signal_registered(signum):
    return lib.uwsgi_signal_registered(signum)

def worker_id():
    return lib.uwsgi.mywid

def mule_id():
    return lib.uwsgi.muleid

def logsize():
    return lib.uwsgi.shared.logsize

def mule_msg_recv_size():
    return lib.uwsgi.mule_msg_recv_size

def request_id():
    wsgi_req = lib.uwsgi.current_wsgi_req()
    return lib.uwsgi.workers[lib.uwsgi.mywid].cores[wsgi_req.async_id].requests

