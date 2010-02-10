import os
uwsgi_os = os.uname()[0]

if uwsgi_os == 'SunOS':
	print '-lsendfile '
