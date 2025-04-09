# uwsgi --master --chdir /opt/graphite/webapp/graphite --module graphite_uwsgi ...
#
#
# this module will update a carbon server (used by the graphite tool: http://graphite.wikidot.com/)
# with requests count made by a Django app (and can track graphite itself as it is a Django app ;)
#
#

import os
import uwsgi
import time
from django.core.handlers.wsgi import WSGIHandler

os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

CARBON_SERVER = "127.0.0.1:2003"


def update_carbon(signum):
    # connect to the carbon server
    carbon_fd = uwsgi.connect(CARBON_SERVER)
    # send data to the carbon server
    uwsgi.send(carbon_fd, "uwsgi.%s.requests %d %d\n" % (uwsgi.hostname, uwsgi.total_requests(), int(time.time())))
    # close the connection with the carbon server
    uwsgi.close(carbon_fd)

# register a new uwsgi signal (signum: 17)
uwsgi.register_signal(17, '', update_carbon)

# attach a timer of 10 seconds to signal 17
uwsgi.add_timer(17, 10)

# the Django app
application = WSGIHandler()
