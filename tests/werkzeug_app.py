import uwsgi

print(uwsgi.opt)
print(uwsgi.magic_table)
from werkzeug.testapp import test_app as application  # NOQA
