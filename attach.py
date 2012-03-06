import struct
import sys
import os

filename = sys.argv[1]

size = os.path.getsize(filename)

f = open(filename, 'r')
print(f.read())
f.close()

print(struct.pack("<Q", size))
