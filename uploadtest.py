def application(env, start_response):


    if env['REQUEST_METHOD'] == 'POST':
    	start_response('200 Ok', [('Content-type', 'text/plain')])
	#for x in env['wsgi.input']:
	#	yield x
	body = env['wsgi.input'].readline()
	print body
	body += env['wsgi.input'].read(100)
	body += env['wsgi.input'].read(100)
	body += env['wsgi.input'].read()
	return body
    else:
    	start_response('200 Ok', [('Content-type', 'text/html')])
        return """
<form method="POST" enctype="multipart/form-data">
	<textarea name="pluto">
	</textarea>
    <input type="test" name="pippo" />
    <input type="submit" value="invia" />
</form>
        """

