import uuid
import uwsgi
import os


def application(env, start_response):

    print(env.__class__)
    print(env['PATH_INFO'])
    print(env['REQUEST_METHOD'])
    print(env['wsgi.input'])

    if env['PATH_INFO'].startswith('/progress/'):
        start_response('200 Ok', [('Content-type', 'application/json')])
        filename = 'foobar/' + env['PATH_INFO'][10:]
        print filename
       	if os.path.exists(filename): 
            return uwsgi.sendfile(filename)
        else:
            return "{ 'state': 'done' }"
	

    if env['REQUEST_METHOD'] == 'POST':
    	start_response('200 Ok', [('Content-type', 'text/plain')])
	#for x in env['wsgi.input']:
	#	yield x
	body = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
	body += env['wsgi.input'].readline()
	#print body
	body += env['wsgi.input'].read(100)
	body += env['wsgi.input'].read(100)
	body += env['wsgi.input'].read()
	return body
    else:
    	start_response('200 Ok', [('Content-type', 'text/html')])
        x_progress_id = str(uuid.uuid4())
        return """
<html>
<head>
<script src="/static/jquery-1.5.1.min.js" /></script>
<script language="Javascript">
var interval;
function redrawProgressBar() {
	interval = setInterval(getData, 1000);
}

function getData() {
	var jsr = $.getJSON("/progress/%s.js",
        	function(data) {
			if (data) {
				if (data.state == 'uploading') {
					$('#progress').html(data.received + '/' + data.size);
					return;
				}
			}
			alert("fine");
			clearInterval(interval);
                }
	);
	jsr.error(function() { clearInterval(interval); });

}
</script>
</head>
<body>
upload progress: <div id="progress"> 0%%</div>
<form method="POST" enctype="multipart/form-data" action="?X-Progress-ID=%s" onsubmit="redrawProgressBar(); return true;">
	<textarea name="pluto">
	</textarea>
    <input type="file" name="pippo" />
    <input type="submit" value="invia" />
</form>
</body>
</html>
        """ % (x_progress_id, x_progress_id)

