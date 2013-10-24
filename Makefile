PYTHON := python
PROFILE := default

all:
	$(PYTHON) uwsgiconfig.py --build $(PROFILE)

clean:
	$(PYTHON) uwsgiconfig.py --clean

check:
	$(PYTHON) uwsgiconfig.py --check
