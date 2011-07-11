import uwsgi
from threading import Thread

if uwsgi.masterpid() == 0:
    raise Exception("you have to enable the uWSGI master process to use this module")

if uwsgi.opt.get('lazy'):
    raise Exception("uWSGI lazy mode is not supporte by this module")

spooler_functions = {}
postfork_chain = []

def get_free_signal():
    for signum in xrange(0, 256):
        if not uwsgi.signal_registered(signum):
            return signum

    raise Exception("No free uwsgi signal available")

def manage_spool_request(vars):
    ret = spooler_functions[vars['ud_spool_func']](vars)
    if not vars.has_key('ud_spool_ret'):
        return ret
    return int(vars['ud_spool_ret'])

def postfork_chain_hook():
    for f in postfork_chain:
        f()

uwsgi.spooler = manage_spool_request
uwsgi.post_fork_hook = postfork_chain_hook

class postfork(object):
    def __init__(self, f):
        postfork_chain.append(f)

class spool(object):

    def spool(self, *args, **kwargs):
        arguments = self.base_dict
        arguments['ud_spool_ret'] = str(uwsgi.SPOOL_OK)
        if len(args) > 0:
            arguments.update(args[0])
        if kwargs:
            arguments.update(kwargs)
        return uwsgi.spool(arguments)

    def __init__(self, f):
        if not uwsgi.opt.has_key('spooler'):
            raise Exception("you have to enable the uWSGI spooler to use the @spool decorator")
        self.f = f
        spooler_functions[f.__name__] = self.f
        self.f.spool = self.spool
	self.base_dict = {'ud_spool_func':self.f.__name__}

class spoolforever(spool):

    def spool(self, *args, **kwargs):
        arguments = self.base_dict
        arguments['ud_spool_ret'] = str(uwsgi.SPOOL_RETRY)
        if len(args) > 0:
            arguments.update(args[0])
        if kwargs:
            arguments.update(kwargs)
        return uwsgi.spool(arguments)

class spoolraw(spool):

    def spool(self, *args, **kwargs):
        arguments = self.base_dict
        if len(args) > 0:
            arguments.update(args[0])
        if kwargs:
            arguments.update(kwargs)
        return uwsgi.spool(arguments)


class rpc(object):

    def __init__(self, name):
        self.name = name

    def __call__(self, f):
        uwsgi.register_rpc(self.name, f)
        return f

class signal(object):

    def __init__(self, num, **kwargs):
        self.num = num
	self.target = kwargs.get('target', '')

    def __call__(self, f):
        uwsgi.register_signal(self.num, self.target, f)
        return f

class timer(object):

    def __init__(self, secs, **kwargs):
        self.num = kwargs.get('signum', get_free_signal())
        self.secs = secs
	self.target = kwargs.get('target', '')

    def __call__(self, f):
        uwsgi.register_signal(self.num, self.target, f)
        uwsgi.add_timer(self.num, self.secs)
        return f

class cron(object):

    def __init__(self, minute, hour, day, month, dayweek, **kwargs):
        self.num = kwargs.get('signum', get_free_signal())
        self.minute = minute
        self.hour = hour
        self.day = day
        self.month = month
        self.dayweek = dayweek
	self.target = kwargs.get('target', '')

    def __call__(self, f):
        uwsgi.register_signal(self.num, self.target, f)
        uwsgi.add_cron(self.num, self.minute, self.hour, self.day, self.month, self.dayweek)
        return f



class rbtimer(object):

    def __init__(self, secs, **kwargs):
        self.num = kwargs.get('signum', get_free_signal())
        self.secs = secs
	self.target = kwargs.get('target', '')

    def __call__(self, f):
        uwsgi.register_signal(self.num, self.target, f)
        uwsgi.add_rb_timer(self.num, self.secs)
        return f

class filemon(object):

    def __init__(self, fsobj, **kwargs):
        self.num = kwargs.get('signum', get_free_signal())
        self.fsobj = fsobj
	self.target = kwargs.get('target', '')

    def __call__(self, f):
        uwsgi.register_signal(self.num, self.target, f)
        uwsgi.add_file_monitor(self.num, self.fsobj)
        return f

class lock(object):
    def __init__(self, f):
        self.f = f

    def __call__(self, *args, **kwargs):
        uwsgi.lock()
        try:
            return self.f(*args, **kwargs)
        finally:
            uwsgi.unlock()

class thread(object):

    def __init__(self, f):
        self.f = f

    def __call__(self, *args):
        t = Thread(target=self.f, args=args)
        t.daemon = True
        t.start()
        return self.f

    
