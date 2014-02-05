my $app = sub {
        my ($env) = @_;
        my $orig = $env->{QUERY_STRING};
        if ($env->{CONTENT_LENGTH} > 0) {
                $env->{'psgi.input'}->read($orig, $env->{CONTENT_LENGTH}, $env->{HTTP_UWSGI_OFFSET});
        }
        return [ 200, ['Content-Type' => 'text/plain'], [$orig."\n"]];
};
