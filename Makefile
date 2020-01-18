PYTHON := python

all:
	$(PYTHON) uwsgiconfig.py --build $(PROFILE)

clean:
	$(PYTHON) uwsgiconfig.py --clean

check:
	$(PYTHON) uwsgiconfig.py --check

plugin.%:
	$(PYTHON) uwsgiconfig.py --plugin plugins/$* $(PROFILE)

tests:
	$(PYTHON) uwsgiconfig.py --build unittest
	cd check && make && make test

%:
	$(PYTHON) uwsgiconfig.py --build $@

.PHONY: all clean check tests
