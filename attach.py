import struct
import sys
import os

filename = sys.argv[1]

size = os.path.getsize(filename)

with open(filename) as f:
    os.write(1, f.read())

os.write(1, (struct.pack("<Q", size)))
