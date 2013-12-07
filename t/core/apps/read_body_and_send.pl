my $app = sub {
	my $env = shift;
	$env->{'psgi.input'}->read(my $body, $env->{CONTENT_LENGTH});
	return [200, ['Content-Type' => 'x-application/binary'], [$body]];
};
