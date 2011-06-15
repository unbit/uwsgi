import uwsgi

class rpc(object):

    def __init__(self, name):
        self.name = name

    def __call__(self, f):
        uwsgi.register_rpc(self.name, f)
        return f

class signal(object):

    def __init__(self, num):
        self.num = num

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        return f
