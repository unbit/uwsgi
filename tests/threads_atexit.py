# https://github.com/unbit/uwsgi/pull/2615
# atexit should be called when reached max-requests.
#
# Start this app:
#
#   $ ./uwsgi --http-socket :8000 --master -L --wsgi-file=tests/threads_atexit.py \
#       --workers 1 --threads 32 --max-requests 40 --min-worker-lifetime 6 --lazy-apps
#
# Access to this app with hey[1]:
#
#   # Do http access for 5 minutes with 32 concurrency
#   $ ./hey -c 32 -z 5m 'http://127.0.0.1:8000/'
#
# Search how many stamp files:
#
#   $ ls uwsgi_worker*.txt | wc -l
#   39  # should be 0
#
# [1] https://github.com/rakyll/hey

import atexit
import os
import sys
import time


pid = os.getpid()
stamp_file = f"./uwsgi_worker{pid}.txt"


with open(stamp_file, "w") as f:
    print(time.time(), file=f)


@atexit.register
def on_finish_worker():
    print(f"removing {stamp_file}", file=sys.stderr)
    os.remove(stamp_file)


def application(env, start_response):
    time.sleep(1)
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [b"Hello World"]
