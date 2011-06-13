from uwsgicc import app

import uwsgi

def hello_world(name):
    return "Hello World %s" % name

uwsgi.register_rpc("hello", hello_world)

application = app
