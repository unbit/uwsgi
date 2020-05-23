#!/bin/sh
# Run from base uwsgi directory
set -e
# export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
./uwsgi --plugin cffi -T \
    --http-socket 0.0.0.0:8080 \
    --env=PYTHONPATH=$HOME/prog/uwsgi:$HOME/prog/uwsgi/plugins/cffi \
    --cffi-init=cffi_dyn_init \
    --cffi-wsgi=helloworld \
    --chdir=$VIRTUAL_ENV/bin \
    --master \
    --touch-reload=$HOME/prog/uwsgi/helloworld.py
