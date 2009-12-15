import uwsgi

import time


def myspooler(env):
	print env
	for i in range(1,100):
		uwsgi.sharedarea_inclong(100)
		time.sleep(1)

uwsgi.spooler = myspooler

def helloworld():
	return 'Hello World'

def increment():
	return "Shared counter is %d\n" % uwsgi.sharedarea_inclong(100)

def force_harakiri():
	time.sleep(60)
	
	

def application(env, start_response):

	start_response('200 OK', [('Content-Type', 'text/plain')])
	yield { '/': helloworld, '/sleep': force_harakiri, '/counter': increment }[env['PATH_INFO']]()

	print env

def gomako():
	from mako.template import Template
	uwsgi.start_response('200 OK', [('Content-Type', 'text/html')])
	yield Template("hello ${data}!").render(data="world")

def goxml():
	import xml.dom.minidom
	doc = xml.dom.minidom.Document()
	foo = doc.createElement("foo")
	doc.appendChild(foo)
	uwsgi.start_response('200 OK', [('Content-Type', 'text/xml')])
	return doc.toxml()
	

uwsgi.fastfuncs.insert(10, gomako)
uwsgi.fastfuncs.insert(11, goxml)

applications = {'/':'application'}
