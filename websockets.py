import uwsgi

def application(e, s):
	print e


	client = e['wsgi.input'].fileno()

	print client

	data = uwsgi.recv_block(client, 8)

	print "data", data, len(data)

	key1 = e['HTTP_SEC_WEBSOCKET_KEY1']
	key2 = e['HTTP_SEC_WEBSOCKET_KEY2']

	total1 = ''
	div1 = 0
	for c in key1:
		if c in '0'..'9':
			total1 += c

	for c in key1:
		if c == ' ':
			div1 += 1

	if div1 == 0:
		raise StopIteration	

	total1 = int(total1) / div1

	total2 = ''
	div2 = 0
	for c in key2:
		if c in '0'..'9':
			total2 += c

	for c in key2:
		if c == ' ':
			div2 += 1

	if div2 == 0:
		raise StopIteration	

	total2 = int(total2) / div1

	
