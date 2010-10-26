import uwsgi

def ciao():
    uwsgi.start_response('200 OK', [ ('Content-type', 'text/plain') ])
    uwsgi.send(str(22+30))

def application(env, start_response):

    start_response('200 Ok', [('Content-type', 'text/html')])

    if env['REQUEST_METHOD'] == 'POST':
        print "getting file..."
        remains = int(env['CONTENT_LENGTH'])
        print remains
        buf = ''
        while remains > 0:
            if remains < 8192:
                buf = env['wsgi.input'].read(remains)
            else:
                buf = env['wsgi.input'].read(8192)
            #print len(buf)
            remains = remains - len(buf)
            #print "remains",remains
        print "upload ready"
        yield env['CONTENT_LENGTH']
    else:
        yield """
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" value="invia" />
</form>
        """

