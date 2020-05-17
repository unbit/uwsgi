#!/bin/sh
set -e
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
./uwsgi --plugin cffi --http-socket 0.0.0.0:8081 --cffi-wsgi=websockets_chat_async --chdir=$HOME/opt/pypy361/bin --env=PYTHONPATH=$HOME/prog/uwsgi:$HOME/prog/uwsgi/plugins/cffi --cffi-init=cffi_dyn_init --master --touch-reload=$PWD/websockets_chat_async.py --async 64 -T
