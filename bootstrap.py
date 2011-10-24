import sys
import uwsgi

print("i am the bootstrap for uwsgi.SymbolsImporter")
sys.meta_path.insert(0, uwsgi.SymbolsImporter())
