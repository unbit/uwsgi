import os
import subprocess


def application(env, start_response):

    boundary = 'uwsgi_mjpeg_frame'

    start_response('200 Ok', [
        ('Cache-Control', 'no-cache'),
        ('Cache-Control', 'private'),
        ('Pragma', 'no-cache'),
        ('Content-Type', 'multipart/x-mixed-replace; boundary=' + boundary),
    ])

    yield "--%s\r\n" % boundary

    while 1:
        yield "Content-Type: image/jpeg\r\n\r\n"
        print(subprocess.call('screencapture -t jpg -m -T 1 screenshot.jpg', shell=True))
        f = open('screenshot.jpg')
        yield env['wsgi.file_wrapper'](f)
        yield "\r\n--%s\r\n" % boundary
        # subprocess.call('./isightcapture -w 640 -h 480 screenshot.jpg', shell=True)
