from uwsgicc import app

import uwsgi

def hello_world(name):
    return "Hello World %s" % name

uwsgi.register_rpc("hello", hello_world)

uwsgi.set_warning_message("uWSGI is running the Control Center")

application = app
