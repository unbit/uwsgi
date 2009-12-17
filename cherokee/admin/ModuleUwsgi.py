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
        'balancer',
        'modifier1',
        'modifier2',
	'pass_wsgi_vars',
	'pass_request_body'
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


        opt = "%s!modifier1" % (self._prefix)
	self.AddPropEntry(table, _('Modifier1'), opt, 'a number between 0 and 255', size=3);

        opt = "%s!modifier2" % (self._prefix)
	self.AddPropEntry(table, _('Modifier2'), opt, 'a number between 0 and 255', size=3);

	opt = "%s!pass_wsgi_vars" % (self._prefix)
	self.AddPropCheck (table, _("Pass WSGI vars"), opt, True,  'pass all the wsgi vars to the application')

	opt = "%s!pass_request_body" % (self._prefix)
	self.AddPropCheck (table, _("Pass Request body"), opt, True,  'pass the request body to the application')

        opt = "%s!balancer" % (self._prefix)
        e = self.AddPropOptions_Reload_Module (table, _("Balancer"), opt,
                                               modules_available(BALANCERS), _(NOTE_BALANCER))

        txt += self.Indent(str(table) + e)

        return txt

    def _op_apply_changes (self, uri, post):

        # Apply modifier1
        opt = "%s!modifier1" % (self._prefix)
        mod1 = post.pop(opt)
        if mod1:
            self._cfg[opt] = mod1

        # Apply modifier2
        opt  = "%s!modifier2" % (self._prefix)
        mod2 = post.pop(opt)
        if mod2:
            self._cfg[opt] = mod2

        # Apply pass_request_body and pass_wsgi_vars
	self.ApplyChangesPrefix (self._prefix, ['pass_wsgi_vars','pass_request_body'], post)

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
