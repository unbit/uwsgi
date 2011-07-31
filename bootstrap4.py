import sys
import uwsgi

sys.meta_path.insert(0, uwsgi.ZipImporter("data://0"))
