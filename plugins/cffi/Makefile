PYTHON := python

cffi_plugin.c: cffi_plugin.py cffi_init.py uwsgiplugin.py _constants.h _uwsgi.h types.h module_bundle.py uwsgi.py
	$(PYTHON) cffi_plugin.py

_constants.h: ../../uwsgi.h constants.py
	$(PYTHON) constants.py

_uwsgi_preprocessed.h: ../../uwsgi.h
	cat ../../uwsgi.h | gcc -E - -I ../../ -D "__attribute__(x)"= > _uwsgi_preprocessed.h

_uwsgi.h: _uwsgi_preprocessed.h filtercdefs.py
	 $(PYTHON) filtercdefs.py _uwsgi_preprocessed.h > _uwsgi.h

clean:
	rm _uwsgi.h _uwsgi_preprocessed.h _constants.h cffi_plugin.c
