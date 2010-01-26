import uwsgi
import struct
import sys


print uwsgi.send_uwsgi_message(sys.argv[1], int(sys.argv[2]), 10, int(sys.argv[3]), struct.pack("i", int(sys.argv[4])))

