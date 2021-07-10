import cffi_greenlets
import cffi_asyncio

cffi_asyncio.setup_asyncio(32)  # is this the same as the --async option?
cffi_greenlets.uwsgi_cffi_setup_greenlets()
cffi_asyncio.async_init()  # should this happen in a postfork hook or at a different phase of config?
