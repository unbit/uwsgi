#!/bin/sh
# Run uwsgi as an interactive Python interpreter.
# ./uwsgi --socket : --plugin cffi --cffi-eval "import IPython; IPython.embed()" --honour-stdin --cffi-home $VIRTUAL_ENV
# repl trick: 
# "import code; code.interact()"
# pypy repl trick. random socket port.
./uwsgi --socket : --plugin cffi --cffi-eval "import _pypy_interact; _pypy_interact.interactive_console()" --honour-stdin --cffi-home $VIRTUAL_ENV