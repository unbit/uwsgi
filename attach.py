import struct
import sys
import os

filename = sys.argv[1]

size = os.path.getsize(filename)

f = open(filename, 'r')
os.write(1, f.read())
f.close()

os.write(1, (struct.pack("<Q", size)))
