
import uwsgi

def application(e,s):

	node = uwsgi.cluster_best_node()
	print node

	if not node:
		print "sorry node unavailable"
		raise StopIteration

	for part in uwsgi.send_message(node, 0, 0, e, 0, e['wsgi.input'].fileno(), uwsgi.cl()):
		yield part 
