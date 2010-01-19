import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from django.conf.urls.defaults import *

urlpatterns = patterns('uwsgi_admin.views',
                        (r'^$', 'index'),
                        (r'^reload/$', 'reload')
                )

