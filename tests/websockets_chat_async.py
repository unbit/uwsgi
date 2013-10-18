#!./uwsgi --http-socket :9090 --async 100 ...
# same chat example but using uwsgi async api
# for pypy + continulets just run:
# uwsgi --http-socket :9090 --pypy-home /opt/pypy --pypy-wsgi-file tests/websockets_chat_async.py --pypy-eval "uwsgi_pypy_setup_continulets()" --async 100
import uwsgi
import time
import redis
import sys

def application(env, sr):

    ws_scheme = 'ws'
    if 'HTTPS' in env or env['wsgi.url_scheme'] == 'https':
        ws_scheme = 'wss'

    if env['PATH_INFO'] == '/':
        sr('200 OK', [('Content-Type','text/html')])
        output = """
    <html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("%s://%s/foobar/");
            s.onopen = function() {
              alert("connected !!!");
              s.send("ciao");
            };
            s.onmessage = function(e) {
		var bb = document.getElementById('blackboard')
		var html = bb.innerHTML;
		bb.innerHTML = html + '<br/>' + e.data;
            };

	    s.onerror = function(e) {
			alert(e);
		}

	s.onclose = function(e) {
		alert("connection closed");
	}

            function invia() {
              var value = document.getElementById('testo').value;
              s.send(value);
            }
          </script>
     </head>
    <body>
        <h1>WebSocket</h1>
        <input type="text" id="testo"/>
        <input type="button" value="invia" onClick="invia();"/>
	<div id="blackboard" style="width:640px;height:480px;background-color:black;color:white;border: solid 2px red;overflow:auto">
	</div>
    </body>
    </html>
        """ % (ws_scheme, env['HTTP_HOST'])
        if sys.version_info[0] > 2:
            return output.encode('latin1')
        return output
    elif env['PATH_INFO'] == '/favicon.ico':
        return ""
    elif env['PATH_INFO'] == '/foobar/':
        uwsgi.websocket_handshake(env['HTTP_SEC_WEBSOCKET_KEY'], env.get('HTTP_ORIGIN', ''))
        print("websockets...")
        r = redis.StrictRedis(host='localhost', port=6379, db=0)
        channel = r.pubsub()
        channel.subscribe('foobar')

        websocket_fd = uwsgi.connection_fd()
        redis_fd = channel.connection._sock.fileno()
        
        while True:
            uwsgi.wait_fd_read(websocket_fd, 3)
            uwsgi.wait_fd_read(redis_fd)
            uwsgi.suspend()
            fd = uwsgi.ready_fd()
            if fd > -1:
                if fd == websocket_fd:
                    msg = uwsgi.websocket_recv_nb()
                    if msg:
                        r.publish('foobar', msg)
                elif fd == redis_fd:
                    msg = channel.parse_response() 
                    print(msg)
                    # only interested in user messages
                    t = 'message'
                    if sys.version_info[0] > 2:
                        t = b'message'
                    if msg[0] == t:
                        uwsgi.websocket_send("[%s] %s" % (time.time(), msg))
            else:
                # on timeout call websocket_recv_nb again to manage ping/pong
                msg = uwsgi.websocket_recv_nb()
                if msg:
                    r.publish('foobar', msg)
