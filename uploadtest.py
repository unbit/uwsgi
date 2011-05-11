def application(env, start_response):


    if env['REQUEST_METHOD'] == 'POST':
    	start_response('200 Ok', [('Content-type', 'text/plain')])
	#for x in env['wsgi.input']:
	#	yield x
	return env['wsgi.input'].readlines()
    else:
    	start_response('200 Ok', [('Content-type', 'text/html')])
        return """
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" value="invia" />
</form>
        """

