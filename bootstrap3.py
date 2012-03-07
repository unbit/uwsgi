import sys
import uwsgi

sys.meta_path.insert(0, uwsgi.SymbolsZipImporter("django_zip:djenv/lib/python2.6/site-packages"))
sys.meta_path.insert(0, uwsgi.SymbolsZipImporter("djapp_zip"))
