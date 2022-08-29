import signal, sys
import time
import uwsgi
import os

print(uwsgi.opt)

sig_timeout = uwsgi.opt.get('test_mule_timeout', 10)
sig_to_send = uwsgi.opt.get('test_signal', signal.SIGINT)

def sig_handler(signum, frame):
    print('Hello from signal', signum)
    time.sleep(int(sig_timeout))
    sys.exit(0)

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGHUP, sig_handler)

time.sleep(1)

os.kill(uwsgi.masterpid(), int(sig_to_send))

while True:
    uwsgi.farm_get_msg()
