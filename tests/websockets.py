import uwsgi
import time

def application(env, sr):

    if env['PATH_INFO'] == '/':
        sr('200 OK', [('Content-Type','text/html')])
        return """
    <html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("ws://raring64.local:8181/foobar/");
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
	<div id="blackboard" style="width:640px;height:480px;background-color:black;color:white;border: solid 2px red">
	</div>
    </body>
    </html>
        """
    elif env['PATH_INFO'] == '/foobar/':
        print "websockets..."
	uwsgi.websocket_channel_join('room001')
        while True:
            msg = uwsgi.websocket_recv()
            print len(msg)
            uwsgi.websocket_send("hello %s = %s" % (time.time(), msg)) 
