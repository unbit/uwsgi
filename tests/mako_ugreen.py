import uwsgi

from mako.template import Template
import time


def application(env, start_response):
    start_response('200 OK', [('Content-Type', 'text/html')])

    mytemplate = Template("<h1>I am Mako at ${thetime}</h1>")
    uwsgi.green_schedule()

    yield mytemplate.render(thetime=time.time())

    for i in range(1, 100):
        mytemplate = Template("Iteration ${thei} at ${thetime}<br/>")
        uwsgi.green_schedule()
        yield mytemplate.render(thei=i, thetime=time.time())
