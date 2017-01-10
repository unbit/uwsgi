# uwsgi --master --plugins=python27 --spooler=/var/spool/uwsgi/ --spooler-import spooler_dir.py
import uwsgi


def spooler_func(env):
    print(uwsgi.spooler_dir())
    return uwsgi.SPOOL_RETRY

uwsgi.spooler = spooler_func
uwsgi.spool({"foo": "bar"})
