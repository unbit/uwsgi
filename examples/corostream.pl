# to run the server
# uwsgi --plugin psgi,coroae --http-socket :9090 --http-socket-modifier1 5 --coroae 8 --psgi examples/corostream.pl --master
# to test it
# curl -D /dev/stdout -N --raw http://localhost:9090/

use Coro::AnyEvent;
use AnyEvent::HTTP;

my $signal_handler = sub {
        my $signum = shift;
        print "i am the signal ".$signum."\n" ;
};

my $signal_timer = sub {
	my $signum = shift;
	print "2 seconds elapsed\n";
};

uwsgi::register_signal(17, '', $signal_handler);
uwsgi::register_signal(30, '', $signal_timer);

# raise the signal 30 every 2 seconds
uwsgi::add_timer(30, 2);

sub streamer {
	$responder = shift;
	# generate the headers and start streaming the response
	my $writer = $responder->( [200, ['Content-Type' => 'text/plain']]);

	$writer->write("Hello, the streaming is starting...\n");

	for(my $i=0;$i<5;$i++) {
		Coro::AnyEvent::sleep 1;
		$writer->write("[".$i."] one seconds elapsed...\n");
	}

	$writer->write("let me show you the coroae plugin source taken from github\n\n");

	# this condvar will allow us to wait for the github response
	my $w = AnyEvent->condvar;

	my $uwsgi_coroae_src = '';

	http_get 'https://raw.github.com/unbit/uwsgi/master/plugins/coroae/coroae.c', sub { $uwsgi_coroae_src = $_[0] ; $w->send;};

	$w->recv;

	$writer->write($uwsgi_coroae_src);

	Coro::AnyEvent::sleep 1;

	$writer->write("now let's raise a uwsgi signal...\n");

	uwsgi::signal(17);

	Coro::AnyEvent::sleep 1;

	$writer->write("another one second elapsed, time to finish.\n");

	Coro::AnyEvent::sleep 1;

	$writer->write("Goodbye\n");

	$writer->close;

	print "the request ended, but we are still here\n";

	Coro::AnyEvent::sleep 1;

	print "another second elapsed, time to end (really)\n";
}

# our PSGI app
my $app = sub {
	my $env = shift;
	return \&streamer;
}
