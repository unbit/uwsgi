#!./uwsgi --plugins http,0:psgi,coroae --https :443,foobar.crt,foobar.key --http-websockets --coroae 40 --psgi tests/websockets_echo.pl

my $app = sub {

	my $env = shift;

	my $ws_scheme = 'ws';
	if (exists($env->{HTTPS}) || $env['psgi.url_scheme'] eq 'https') {
		$ws_scheme = 'wss';
	}

	if ($env->{PATH_INFO} eq '/') {
my $body = <<EOF;
<html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("$ws_scheme://$env->{HTTP_HOST}/foobar/");
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
        	return ['200', ['Content-Type' => 'text/html'], [$body]];
	}
	elsif ($env->{PATH_INFO} eq '/foobar/') {
		uwsgi::websocket_handshake($env->{HTTP_SEC_WEBSOCKET_KEY}, $env->{HTTP_ORIGIN});
        	print "websockets...\n";
		while(1) {
			my $msg = uwsgi::websocket_recv;
			uwsgi::websocket_send('['.time().'] '.$msg);
		}
	}

}
