import uwsgi
import time
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.admin.views.decorators import staff_member_required
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect


def index(request):
	workers = uwsgi.workers()
	total_load = time.time() - uwsgi.started_on
	for w in workers:
		w['load'] = (100 * (w['running_time']/1000))/total_load
		w['last_spawn_str'] = time.ctime(w['last_spawn'])

	return render_to_response('uwsgi.html', {'masterpid': uwsgi.masterpid(),
						'started_on': time.ctime(uwsgi.started_on),
						'buffer_size': uwsgi.buffer_size,
						'total_requests': uwsgi.total_requests(),
						'numproc': uwsgi.numproc,
						'workers': workers,
						}, RequestContext(request, {}))
index = staff_member_required(index)

def reload(request):
	if uwsgi.masterpid() > 0:
		uwsgi.reload()
		request.user.message_set.create(message="uWSGI reloaded")
	else:
		request.user.message_set.create(message="The uWSGI master process is not active")

	return HttpResponseRedirect(reverse(index))

reload = staff_member_required(reload)
