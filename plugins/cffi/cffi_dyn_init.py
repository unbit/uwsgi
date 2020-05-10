"""
cffi init, not baked into .so
"""

from cffi_plugin import ffi, lib

@ffi.def_extern()
def uwsgi_cffi_after_request(wsgi_req):
    print("overridden callback!")
    lib.log_request(wsgi_req)
