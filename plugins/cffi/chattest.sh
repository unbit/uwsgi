#!/bin/sh
# Run from base uwsgi directory
set -e
export PYTHONPATH=$PWD:$PWD/plugins/cffi
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
./uwsgi \
  --master \
  --enable-threads \
  --plugin=cffi \
  --cffi-init=cffi_setup_asyncio \
  --async=32 \
  --http-socket=:8080 \
  --manage-script-name \
  --mount=/wsgi=helloworld \
  --mount=/=starlettetest:app \
  --chdir=$VIRTUAL_ENV/bin \
  --touch-reload $PWD/starlettetest.py \
  --touch-reload $PWD/plugins/cffi/cffi_asyncio.py
