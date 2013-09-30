import array
def application(e, sr):
    sr('200 OK', [('Content-Type','text/html')])
    a = array.array('b',[54,55,56,57])
    yield a
    yield bytearray(b'abcdef')
    yield b'ciao'
