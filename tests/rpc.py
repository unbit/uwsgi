import uwsgi


def hello():
    return "Hello World"

print uwsgi.register_rpc("hello", hello)
