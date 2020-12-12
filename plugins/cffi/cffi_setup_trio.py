import cffi_greenlets
import cffi_trio

# the order of these steps is important
cffi_trio.setup_trio(32)  # is this the same as the --async option?
cffi_greenlets.uwsgi_cffi_setup_greenlets()
cffi_trio.trio_init()
