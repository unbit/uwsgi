
import cffi_greenlets

cffi_greenlets.uwsgi_cffi_setup_greenlets()

import cffi_asyncio

cffi_asyncio.async_init()
cffi_asyncio.setup_asyncio(32)  # is this the same as the --async option?
