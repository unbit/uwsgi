#!./uwsgi --http-socket :9090 --coroae 100 --psgi tests/websockets_chat.pl
use Coro::AnyEvent;
use AnyEvent::Redis;

# Coro::AnyEvent uWSGI/PSGI websocket app
# you can build a Coro::AnyEvent-enabled uWSGI binary with 'make coroae'
# note: we need two redis connections, one for publishing and one for subscribing

my $app = sub {
	my ($env) = @_;

	my $ws_scheme = 'ws';
	$ws_scheme = 'wss' if ($env->{'HTTPS'} || $env->{'wsgi.url_scheme'} eq 'https');

	if ($env->{'PATH_INFO'} eq '/') {
		my $host = $env->{'HTTP_HOST'};
		my $html = <<EOF;

    <html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("$ws_scheme://$host/foobar/");
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
		return [200, ['Content-Type' => 'text/html'], [$html]];
	}
	elsif ($env->{'PATH_INFO'} eq '/favicon.ico') {
        	return [404, [], []];
	}
	elsif ($env->{'PATH_INFO'} eq '/foobar/') {
		# when 1 something was wrong and we need to close the connection
		my $error = 0;
		# when 1 there is something in the websocket
		my $websocket_event = 0;
		# when defined there is a redis message available
		my $redis_message = undef;

		# do the handshake
		uwsgi::websocket_handshake($env->{'HTTP_SEC_WEBSOCKET_KEY'}, $env->{'HTTP_ORIGIN'});
        	print "websockets...\n" ;

		# this condvar will allow us to wait for events
		my $w = AnyEvent->condvar;

		# connect to redis
		my $redis = AnyEvent::Redis->new(
			host => '127.0.0.1',
			port => 6379,
			encoding => 'utf8',
			on_error => sub { warn @_; $error = 1; $w->send; },
			on_cleanup => sub { warn "Connection closed: @_"; $error = 1; $w->send; },
		);

		# subscribe to the 'foobar' channel
		$redis->subscribe('foobar', sub {
			my ($message, $channel) = @_;
			$redis_message = $message;
			# wakeup !!!
			$w->send;
		});

		# open a second connection to publish messages
		my $redis_publisher = AnyEvent::Redis->new(
                        host => '127.0.0.1',
                        port => 6379,
                        encoding => 'utf8',
                        on_error => sub { warn @_; $error = 1; $w->send; },
                        on_cleanup => sub { warn "Connection closed: @_"; $error = 1; $w->send; },
                );

		# start waiting for read events in the websocket
        	my $ws = AnyEvent->io( fh => uwsgi::connection_fd, poll => 'r', cb => sub {
				$websocket_event = 1;	
				# wakeup !!!
				$w->send;
			}
		);
        
		# the main loop
		for(;;) {
			# here we block until an event is available
			$w->recv;
			break if $error;
			# any websocket message available ?
			if ($websocket_event) {
				my $msg = uwsgi::websocket_recv_nb;
				$redis_publisher->publish('foobar', $msg) if $msg;
				$websocket_event = 0;
			}
			# any redis message available ?
			if ($redis_message) {	
				uwsgi::websocket_send('['.time().'] '.$redis_message);
				$redis_message = undef;
			}
			$w = AnyEvent->condvar;
		}
	}	
}
