all:
	python uwsgiconfig.py --build

clean:
	python uwsgiconfig.py --clean

check:
	python uwsgiconfig.py --check
