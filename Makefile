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

docker-test:
	docker build -t uwsgi-build -f docker/Dockerfile docker
	docker run --rm -v $(PWD):/uwsgi:delegated -it --entrypoint /bin/bash uwsgi-build -c 'cd /uwsgi; make tests'

%:
	$(PYTHON) uwsgiconfig.py --build $@

.PHONY: tests docker-test
