python_bin=$(if $(PYTHON_BIN), $(PYTHON_BIN), python)

all:
	$(python_bin) uwsgiconfig.py --build

clean:
	$(python_bin) uwsgiconfig.py --clean

check:
	$(python_bin) uwsgiconfig.py --check
