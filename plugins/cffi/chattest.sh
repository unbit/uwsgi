#!/bin/sh
# Run from base uwsgi directory
set -e
export PYTHONPATH=$PWD:$PWD/plugins/cffi
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
authbind --deep ./uwsgi \
  --master \
  --enable-threads \
  --plugin=cffi \
  --cffi-init=cffi_setup_asyncio \
  --async=32 \
  --http=[::]:80 \
  --http-websockets \
  --http-timeout=40 \
  --manage-script-name \
  --mount=/=starlettetest:app \
  --mount=/wsgi=$PWD/examples/welcome3.py \
  --mount=/welcome=$PWD/examples/welcome.py \
  --chdir=$VIRTUAL_ENV/bin \
  --touch-reload $PWD/starlettetest.py \
  --touch-reload $PWD/plugins/cffi/cffi_asyncio.py
