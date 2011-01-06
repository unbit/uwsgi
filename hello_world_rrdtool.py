import uwsgi
import time
import rrdtool

# rrdtool create test.rrd --start 1270879004 -s 10 DS:requests:COUNTER:300:U:U RRA:AVERAGE:0.5:3:105120

s_freq = 10

# this task will be executed every s_freq seconds
def rrdtool_updater(sig, sec):
	rrdtool.update('test.rrd', str(int(time.time()))+':'+str(uwsgi.total_requests()))

	
uwsgi.register_timer(0, s_freq, uwsgi.KIND_WORKER, rrdtool_updater)
	


def hello_world(env, start_response):
	start_response('200 Ok', [('Content-type', 'text/plain')])
	return 'Hello world !'


def graph(env, start_response):
	start_response('200 Ok', [('Content-type', 'image/png')])
	now = int(time.time())
	graph_range = (3600*24)
	rrdtool.graph('uwsgi_graph.png', '--start', str(now - graph_range), '--end', str(now), 'DEF:urequests=test.rrd:requests:AVERAGE', 'LINE2:urequests#00FF00')
	# send file to client
	uwsgi.sendfile('uwsgi_graph.png')

uwsgi.applications = {'/': hello_world, '/graph':graph}
