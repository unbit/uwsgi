
class UWSGIState(object):
    def __init__(self):
        self.callables = {} # a mapping from app-id to application

class WSGIRequest(object):
    pass

uwsgi_global_state = UWSGIState() # :-((
