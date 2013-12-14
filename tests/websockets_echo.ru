#!./uwsgi --plugins http,0:rack,fiber --https :443,foobar.crt,foobar.key --http-websockets --fiber --rack tests/websockets_echo.ru --async 100

class WebsocketEcho

        def call(env)

		ws_scheme = 'ws'
		if env.has_key?('HTTPS') or env['rack.url_scheme'] == 'https'
			ws_scheme = 'wss'
		end

		if env['PATH_INFO'] == '/'
			body = <<EOF
<html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("#{ws_scheme}://#{env['HTTP_HOST']}/foobar/");
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

EOF

        		return [200, { 'Content-Type' => 'text/html'}, [body]]
		elsif env['PATH_INFO'] == '/foobar/'
			UWSGI::websocket_handshake(env['HTTP_SEC_WEBSOCKET_KEY'], env['HTTP_ORIGIN'])
        		puts "websockets..."
			loop do
				msg = UWSGI::websocket_recv
				UWSGI::websocket_send("[#{Time.now}] #{msg}")
			end
		end
        end
end

run WebsocketEcho.new
