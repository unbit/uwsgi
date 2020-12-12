#!/bin/sh
# Run from base uwsgi directory
set -e
export PYTHONPATH=$PWD:$PWD/plugins/cffi
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
authbind --deep ./uwsgi \
  --master \
  --enable-threads \
  --listen 64 \
  --plugin=cffi \
  --cffi-init=cffi_setup_trio \
  --async=64 \
  --http=[::]:80 \
  --http-websockets \
  --manage-script-name \
  --mount=/=starlettetest:app \
  --mount=/wsgi=$PWD/examples/welcome3.py \
  --chdir=$VIRTUAL_ENV/bin \
  --touch-reload $PWD/starlettetest.py \
  --touch-reload $PWD/plugins/cffi/cffi_trio.py


# --cffi-home=$VIRTUAL_ENV \
