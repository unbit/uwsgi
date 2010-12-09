import uwsgi
import string
import hashlib
import struct

def to_ws_num(value):
	num = ''
	div = 0

	for c in value:
		if c in string.digits:
			num += c
		elif c == ' ':
			div += 1

	return int(num)/div

def application(e, start_response):
	print e


	client = e['wsgi.input'].fileno()

	print client

	data = uwsgi.recv_block(client, 8)

	print "data", data, len(data)

	key1 = to_ws_num(e['HTTP_SEC_WEBSOCKET_KEY1'])
	key2 = to_ws_num(e['HTTP_SEC_WEBSOCKET_KEY2'])

	response = hashlib.md5( struct.pack('>II', key1, key2) + data).digest()

	
	print response
	
	start_response('101 WebSocket Protocol Handshake',[
		('Upgrade', 'WebSocket'),
		('Connection', 'Upgrade'),
		('Sec-WebSocket-Origin', e.get('HTTP_ORIGIN')),
		('Sec-WebSocket-Location','ws://%s%s%s' % (e.get('HTTP_HOST'), e.get('SCRIPT_NAME'), e.get('PATH_INFO')) ),
		('Sec-WebSocket-Protocol', e.get('HTTP_SEC_WEBSOCKET_PROTOCOL', 'default'))
		])

	yield response

	message = uwsgi.recv_frame(client, '\x00', '\xff')
	while message:
		print message
		uwsgi.signal(-17)
		yield '\x00' + message + '\xff'
		if len(message) == 0:
			raise StopIteration
		message = uwsgi.recv_frame(client, '\x00', '\xff')
