#!./uwsgi --https :8443,foobar.crt,foobar.key --http-raw-body --gevent 100 --module tests.websockets_echo
import uwsgi
import time

def application(env, sr):
    
    ws_scheme = 'ws'
    if 'HTTPS' in env or env['wsgi.url_scheme'] == 'https':
        ws_scheme = 'wss'
    
    if env['PATH_INFO'] == '/':
        sr('200 OK', [('Content-Type','text/html')])
        return """
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
    elif env['PATH_INFO'] == '/foobar/':
        uwsgi.websocket_handshake(env['HTTP_SEC_WEBSOCKET_KEY'], env.get('HTTP_ORIGIN', ''))
        print "websockets..."
        while True:
            msg = uwsgi.websocket_recv()
            uwsgi.websocket_send("[%s] %s" % (time.time(), msg))
