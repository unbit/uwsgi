sub streamer {
	my $responder = shift;

	my $writer = $responder->([ 200, [ 'Content-Type', 'text/html' ]]);

	my @chunks = ('One', 'Two', 'Three');

	foreach(@chunks) {
		uwsgi::async_sleep(1);
		# something like $env->{'psgix.suspend'}(); ???
		uwsgi::suspend();
		$writer->write($_."<br/>");
	}

	$writer->close;

}
my $app = sub {

	my $env = shift;

	return \&streamer;
};
