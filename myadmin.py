import uwsgi
import struct
import sys

print sys.argv

chunks = uwsgi.send_message(sys.argv[1], 10, int(sys.argv[2]), '')

pkt = ''

for chunk in chunks:
    print chunk,len(chunk)
    pkt += chunk

print len(pkt)
print struct.unpack("I", pkt)

