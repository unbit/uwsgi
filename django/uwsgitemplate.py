from django.template.base import TemplateDoesNotExist
from django.template.loader import BaseLoader
from django.conf import settings

try:
    import uwsgi
    on_uwsgi = True
except:
    on_uwsgi = False




class Loader(BaseLoader):

    is_usable = on_uwsgi

    def symbolize(self, name):
        return name.replace('.','_').replace('/','_').replace('-','_')

    def load_template_source(self, template_name, template_dirs=None):
        filename = 'templates_' + self.symbolize(template_name)
        for app in settings.INSTALLED_APPS:
            try:
                symbol = "%s_%s" % (self.symbolize(app), filename)
                return (uwsgi.embedded_data(symbol), "sym://%s" % symbol)
            except:
                pass
        raise TemplateDoesNotExist(template_name)
