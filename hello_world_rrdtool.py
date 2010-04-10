import uwsgi
import time
import rrdtool

# rrdtool create test.rrd --start 1270879004 -s 10 DS:requests:COUNTER:300:U:U RRA:AVERAGE:0.5:3:105120

s_freq = 10

# this is a cron emulator done with the Spooler :)
def rrdtool_updater(env):
	uwsgi.set_spooler_frequency(s_freq)
	rrdtool.update('../test.rrd', str(int(time.time()))+':'+str(uwsgi.total_requests()))
	uwsgi.send_to_spooler({})

	
uwsgi.spooler = rrdtool_updater
	


def hello_world(env, start_response):
	start_response('200 Ok', [('Content-type', 'text/plain')])
	yield 'Hello world !'


def graph(env, start_response):
	start_response('200 Ok', [('Content-type', 'image/png')])
	now = int(time.time())
	graph_range = (3600*24)
	rrdtool.graph('uwsgi_graph.png', '--start', str(now - graph_range), '--end', str(now), 'DEF:urequests=test.rrd:requests:AVERAGE', 'LINE2:urequests#00FF00')
	fd = open('uwsgi_graph.png', 'r')
	# send file to browser
	return env['wsgi.file_wrapper'](fd, 4096)

# start the simil-cron
uwsgi.send_to_spooler({})


uwsgi.applications = {'/': hello_world, '/graph':graph}
