import uwsgi

if uwsgi.masterpid() == 0:
    raise Exception("you have to enable the uWSGI master process to use this module")

if uwsgi.opt.get('lazy'):
    raise Exception("uWSGI lazy mode is not supporte by this module")

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

class timer(object):

    def __init__(self, num, secs):
        self.num = num
        self.secs = secs

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_timer(self.num, self.secs)
        return f

class rbtimer(object):

    def __init__(self, num, secs):
        self.num = num
        self.secs = secs

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_rb_timer(self.num, self.secs)
        return f

class filemon(object):

    def __init__(self, num, fsobj):
        self.num = num
        self.fsobj = fsobj

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_file_monitor(self.num, self.fsobj)
        return f
