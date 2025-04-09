import uwsgi
import struct
import sys

print(sys.argv)
if len(sys.argv) == 3:
    chunks = uwsgi.send_message(sys.argv[1], 10, int(sys.argv[2]), '')

    pkt = ''

    for chunk in chunks:
        pkt += chunk

    print("%d = %d" % (int(sys.argv[2]), struct.unpack("I", pkt)[0]))
elif len(sys.argv) == 4:
    uwsgi.send_message(sys.argv[1], 10, int(sys.argv[2]), struct.pack("I", int(sys.argv[3])))
