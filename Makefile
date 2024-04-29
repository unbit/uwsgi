PYTHON := python3

all:
	$(PYTHON) uwsgiconfig.py --build $(PROFILE)

clean:
	$(PYTHON) uwsgiconfig.py --clean
	cd unittest && make clean

check:
	$(PYTHON) uwsgiconfig.py --check

plugin.%:
	$(PYTHON) uwsgiconfig.py --plugin plugins/$* $(PROFILE)

unittests:
	$(PYTHON) uwsgiconfig.py --build unittest
	cd unittest && make test

%:
	$(PYTHON) uwsgiconfig.py --build $@
