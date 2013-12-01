import uwsgi
import os

def application(env, start_response):

	boundary = 'uwsgi_mjpeg_frame'

	start_response('200 Ok', [

				('Cache-Control', 'no-cache'),
				('Cache-Control', 'private'),
				('Pragma', 'no-cache'),
				('Content-Type', 'multipart/x-mixed-replace; boundary=' + boundary),
				]
			)

	yield "--%s\r\n" % boundary

	while 1:
		yield "Content-Type: image/jpeg\r\n\r\n"
		print os.system('screencapture -t jpg -m -T 1 screenshot.jpg')
		f = open('screenshot.jpg')
                yield env['wsgi.file_wrapper'](f)
		yield "\r\n--%s\r\n" % boundary
		#os.system('./isightcapture -w 640 -h 480 screenshot.jpg')
