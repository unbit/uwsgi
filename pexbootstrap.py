import os
import sys
import pex.pex_bootstrapper

def activate_pex():
    entry_point = os.environ.get('UWSGI_PEX')
    if not entry_point:
        sys.stderr.write('couldnt determine pex from UWSGI_PEX environment variable, bailing!\n')
        sys.exit(1)

    sys.stderr.write('entry_point=%s\n' % entry_point)

    sys.path[0] = os.path.abspath(sys.path[0])
    sys.path.insert(0, entry_point)
    sys.path.insert(0, os.path.abspath(os.path.join(entry_point, '.bootstrap')))

    pex.pex_bootstrapper.bootstrap_pex_env(entry_point)

    sys.stderr.write('sys.path=%s\n\n' % sys.path)

    return entry_point

activate_pex()
