import mmap
import os
import struct
import array
import time
import sys
from optparse import OptionParser

class Cache:

    def __init__(self, filename, cache_slots, block_size=65536, sample_sleep=1):

        self.block_size = block_size
        self.cache_slots = cache_slots

        self.key_size = 2048
        self.item_size = 2 + 2 + 4 + 8 + 8 + 8 + 8 + 8 + self.key_size
        self.block_size_start = self.item_size * self.cache_slots

        fd = os.open(filename, os.O_RDONLY)
        self.cache_store = mmap.mmap(fd, 0, mmap.MAP_SHARED, mmap.PROT_READ)

        self.sample_sleep = sample_sleep
        self.samples = 0
        self.history = []
        self.cache_full = 0
        self.cache_empty = 0
        self.cache_items = 0
        self.block_sizes = 0

    def store_read_item_block(self, position):
        pos = self.cache_store.tell()
        # uwsgi cache stores cache entries first and then the blocks
        self.cache_store.seek(self.block_size_start + (position * self.block_size))
        buf = self.cache_store.read(self.block_size)
        self.cache_store.seek(pos)
        return buf

    def store_read_item(self, position):
        buf = self.cache_store.read(self.item_size)
        fields = struct.unpack_from('@HHIQQQQQ2048c', buf)
        key = array.array('c', fields[8:self.key_size+8]).tostring().rstrip('\x00')

        if [x for x in key if x!= '\x00']:
            buf = self.store_read_item_block(position)
            value = array.array('c', buf).tostring().rstrip('\x00')
        else:
            value = ''
        return (position, key, value, len(value))

    def read(self):
        data = [self.store_read_item(i) for i in range(self.cache_slots)]
        self.cache_store.seek(0)
        self.update_stats(data)
        if self.sample_sleep:
            time.sleep(self.sample_sleep)
        return data
 
    def update_stats(self, data):
        # data is a list of (position, key, value, len(value)) tuples
        items = len([1 for x in data if x[3] > 0])
        self.cache_items += items
        full, empty = items == self.cache_slots, items == 0
        if full:
            self.cache_full += 1
        if empty:
            self.cache_empty += 1
        self.samples += 1
        block_sizes = sum([x[3] for x in data])
        self.block_sizes += block_sizes
        self.history.append({'full': full, 'empty': empty, 'data': data, \
            'items': items, 'block_sizes': block_sizes})

    def dump(self):
        return {
            'samples': self.samples,
            'history': self.history,
            'cache_slots': self.cache_slots,
            'sample_sleep': self.sample_sleep, 
            'cache_empty': self.cache_empty,
            'cache_full': self.cache_full,
            'cache_items': self.cache_items,
            'block_sizes': self.block_sizes,
         }

    def show_dump(self):
        d = self.dump()
        print
        print "Recorded %d samples (%d second(s) sleep between samples)" % \
            (d['samples'], d['sample_sleep'])
        print "Cache empty %d times, full %d times, %.2f items on average" % \
            (d['cache_empty'], d['cache_full'], d['cache_items'] / d['samples'])
        print "Block size average size: %d bytes" % \
            (d['block_sizes'] / d['cache_items'] * 8)
        print "Data in cache average: %d bytes" % \
            (d['block_sizes'] / d['samples'] * 8)

def main(options):
    cache = Cache(options.cache_store, options.cache_slots, options.block_size,
        options.sleep_time)
    print "Recording..."
    while True:
        try:
            data = cache.read()
        except KeyboardInterrupt:
            cache.show_dump()
            sys.exit(0)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-s", "--cache-slots", dest="cache_slots", type="int",
        help="Slots available in the cache, uwsgi cache option")
    parser.add_option("-c", "--cache-store", dest="cache_store", default="uwsgi.cache",
        help="The filename of the cache store, uwsgi cache-store option. Default: uwsgi.cache")
    parser.add_option("-b", "--block-size", dest="block_size", default=65536, type="int",
        help="The size of the cache block, uwsgi cache-blocksize option. Default: 65536")
    parser.add_option("-t", "--sleep-time", dest="sleep_time", default=1, type="int",
        help="The time to sleep between each sample. Default: 1")

    (options, args) = parser.parse_args()
    if not options.cache_slots:
        parser.error('Option -s / --cache-slots is mandatory')
    main(options)
