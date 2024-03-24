#!/bin/sh
# Run from base uwsgi directory
set -e
# export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
# build uwsgi
python uwsgiconfig.py --build nolang
# build plugin
python uwsgiconfig.py -p plugins/cffi nolang
# run
./uwsgi --plugin cffi -T \
    --http-socket 0.0.0.0:8080 \
    --single-interpreter \
    --async=100 \
    --cffi-eval "import cffi_greenlets; cffi_greenlets.uwsgi_cffi_setup_greenlets()" \
    --env=PYTHONPATH=$HOME/prog/uwsgi:$HOME/prog/uwsgi/plugins/cffi \
    --cffi-wsgi=$PWD/tests/websockets_chat_async.py \
    --manage-script-name \
    --mount=/app=$PWD/examples/welcome3.py \
    --chdir=$VIRTUAL_ENV/bin \
    --master \
    --cffi-eval "import sys; print('executable:', sys.executable)"
