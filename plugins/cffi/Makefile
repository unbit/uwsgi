cffi_plugin.c: cffi_plugin.py cffi_init.py uwsgiplugin.py _constants.h _uwsgi.h types.h
	python cffi_plugin.py

_constants.h: ../../uwsgi.h constants.py
	python constants.py

_uwsgi_preprocessed.h: ../../uwsgi.h
	cat ../../uwsgi.h | gcc -E - -D "__attribute__(x)"= > _uwsgi_preprocessed.h

_uwsgi.h: _uwsgi_preprocessed.h filtercdefs.py
	 python filtercdefs.py _uwsgi_preprocessed.h > _uwsgi.h

clean:
	rm _uwsgi.h _uwsgi_preprocessed.h _constants.h cffi_plugin.c
