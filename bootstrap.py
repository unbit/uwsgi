import sys
import imp
import uwsgi

class uWSGISymbolImporter(object):

    def find_module(self, fullname, path=None):
        self.path = None
        symname = fullname.replace('.','_')
        try:
            self.symbol = "%s_py" % symname
            self.code = uwsgi.embedded_data(self.symbol)
            return self
        except:
            try:
                self.symbol = "%s___init___py" % symname
                self.code = uwsgi.embedded_data(self.symbol)
                self.path = "sym://%s" % symname
                return self
            except:
                pass

    def load_module(self, fullname):
        if fullname in sys.modules:
            mod = sys.modules[fullname]
        else:
            mod = sys.modules.setdefault(fullname, imp.new_module(fullname))

        mod.__file__ = "sym://%s" % self.symbol
        mod.__path__ = self.path
        mod.__name__ = fullname
        mod.__loader__ = self
        mod.__package__ = '.'.join(fullname.split('.')[:-1])

        exec uwsgi.embedded_data(self.symbol) in mod.__dict__

        return mod


sys.meta_path.append(uWSGISymbolImporter())
