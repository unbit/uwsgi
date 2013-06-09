import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

(addr, port) = sys.argv[1].split(':')
s.connect((addr, int(port)))

s.send("POST /send HTTP/1.1\r\n")
s.send("Transfer-Encoding: chunked\r\n\r\n")

while True:
    msg = raw_input("msg >> ")
    s.send("%X\r\n%s\r\n" % (len(msg), msg))
