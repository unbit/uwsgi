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


	yield "--%s\n" % boundary

	while 1:
		yield "Content-Type: image/jpeg\r\n\r\n"
		uwsgi.sendfile('screenshot.jpg')
		yield "--%s\n" % boundary
		#os.system('./isightcapture -w 640 -h 480 screenshot.jpg')
		#os.system('screencapture -m -T 1 screenshot.jpg')
