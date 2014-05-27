import os
if 'UWSGI_AS_CPYEXT' in os.environ:
    execfile('%s.cpyext.py' % __file__.rpartition('.py')[0])
else:
    execfile('%s.binary.py' % __file__.rpartition('.py')[0])
