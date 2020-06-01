#!/bin/sh
# Run from base uwsgi directory
set -e
export C_INCLUDE_PATH=/usr/local/opt/openssl\@1.1/include
python ./uwsgiconfig.py -p plugins/cffi nolang
./uwsgi --plugin cffi -T --async 32 --http-socket :8080 --mount=/=websockets_chat_asyncio --chdir $VIRTUAL_ENV/bin --touch-reload $PWD/tests/websockets_chat_asyncio.py --master
