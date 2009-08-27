from Form import *
from Table import *
from Module import *
from validations import *
from consts import *

# For gettext
N_ = lambda x: x

from ModuleCgi import *
from ModuleBalancer import NOTE_BALANCER

HELPS = [
    ('modules_handlers_uwsgi', "UWSGI")
]

class ModuleUwsgi (ModuleCgiBase):
    PROPERTIES = ModuleCgiBase.PROPERTIES + [
        'balancer'
    ]

    def __init__ (self, cfg, prefix, submit):
        ModuleCgiBase.__init__ (self, cfg, prefix, 'uwsgi', submit)

        self.show_script_alias  = False
        self.show_change_uid    = False
        self.show_document_root = True

    def _op_render (self):
        txt = ModuleCgiBase._op_render (self)

        txt += '<h2>%s</h2>' % (_('UWSGI specific'))

        table = TableProps()
        prefix = "%s!balancer" % (self._prefix)
        e = self.AddPropOptions_Reload_Module (table, _("Balancer"), prefix, 
                                               modules_available(BALANCERS), _(NOTE_BALANCER))
        txt += self.Indent(str(table) + e)
        return txt

    def _op_apply_changes (self, uri, post):
        # Apply balancer changes
        pre  = "%s!balancer" % (self._prefix)

        new_balancer = post.pop(pre)
        if new_balancer:
            self._cfg[pre] = new_balancer

        cfg  = self._cfg[pre]
        if cfg and cfg.value:
            name = cfg.value
            props = module_obj_factory (name, self._cfg, pre, self.submit_url)
            props._op_apply_changes (uri, post)

        # And CGI changes
        return ModuleCgiBase._op_apply_changes (self, uri, post)
