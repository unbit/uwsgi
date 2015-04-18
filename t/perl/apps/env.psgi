use strict;
use warnings;

sub {
    my $env = shift;

    my $body = join "\n", map "$_\n$env->{$_}", sort keys %$env;

    [ 200, [ 'Content-type' => 'text/plain' ], [$body] ];
};
