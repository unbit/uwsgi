import uwsgi

if uwsgi.masterpid() == 0:
    raise Exception("you have to enable the uWSGI master process to use this module")

if uwsgi.opt.get('lazy'):
    raise Exception("uWSGI lazy mode is not supporte by this module")

spooler_functions = {}

def get_free_signal():
    for signum in xrange(0, 256):
        if not uwsgi.signal_registered(signum):
            return signum

    raise Exception("No free uwsgi signal available")

def manage_spool_request(vars):
    ret = spooler_functions[vars['ud_spool_func']](vars)
    if not spooler_functions[vars['ud_spool_func']].ret:
        return ret
    return spooler_functions[vars['ud_spool_func']].ret

uwsgi.spooler = manage_spool_request


class spool(object):

    def spool(self, *args, **kwargs):
        self.f.ret = uwsgi.SPOOL_OK
        arguments = self.base_dict
        if len(args) > 0:
            arguments.update(args[0])
        if kwargs:
            arguments.update(kwargs)
        return uwsgi.spool(arguments)

    def __init__(self, f):
        if not uwsgi.spooler_pid:
            raise Exception("you have to enable the uWSGI spooler to use the @spool decorator")
        spooler_functions[f.__name__] = f
        f.spool = self.spool
	self.base_dict = {'ud_spool_func':f.__name__}
        self.f = f

class spoolforever(spool):

    def spool(self, *args, **kwargs):
        self.f.ret = uwsgi.SPOOL_RETRY
        arguments = self.base_dict
        if len(args) > 0:
            arguments.update(args[0])
        if kwargs:
            arguments.update(kwargs)
        return uwsgi.spool(arguments)

class spoolraw(spool):

    def spool(self, *args, **kwargs):
        self.f.ret = None
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

    def __init__(self, num):
        self.num = num

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        return f

class timer(object):

    def __init__(self, secs, num=None):
        if num:
            self.num = num
        else:
            self.num = get_free_signal()
        self.secs = secs

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_timer(self.num, self.secs)
        return f

class cron(object):

    def __init__(self, minute, hour, day, month, dayweek, num=None):
        if num:
            self.num = num
        else:
            self.num = get_free_signal()
        self.minute = minute
        self.hour = hour
        self.day = day
        self.month = month
        self.dayweek = dayweek

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_cron(self.num, self.minute, self.hour, self.day, self.month, self.dayweek)
        return f



class rbtimer(object):

    def __init__(self, secs, num=None):
        if num:
            self.num = num
        else:
            self.num = get_free_signal()
        self.secs = secs

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_rb_timer(self.num, self.secs)
        return f

class filemon(object):

    def __init__(self, fsobj, num=None):
        if num:
            self.num = num
        else:
            self.num = get_free_signal()
        self.fsobj = fsobj

    def __call__(self, f):
        uwsgi.register_signal(self.num, "", f)
        uwsgi.add_file_monitor(self.num, self.fsobj)
        return f
