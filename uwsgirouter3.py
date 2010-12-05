
import uwsgi

current_node = 0

def application(e,s):

	global current_node

	nodes = uwsgi.cluster_nodes()
	print nodes

	if len(nodes) == 0:
		print "no cluster node available"
		raise StopIteration

	if current_node >= len(nodes):
		current_node = 0

	node = nodes[current_node]

	for part in uwsgi.send_message(node, 0, 0, e, 0, e['wsgi.input'].fileno(), uwsgi.cl()):
		yield part 

	current_node+=1
