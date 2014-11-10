use strict;
use warnings;

{
    package psgix::harakiri::tester;
    sub DESTROY { print STDERR "$$: Calling DESTROY\n" }
}

sub {
    my $env = shift;

    die "PANIC: We should support psgix.harakiri here" unless $env->{'psgix.harakiri'};

    $env->{'psgix.harakiri.tester'} = bless {} => 'psgix::harakiri::tester';
    my $harakiri = $env->{QUERY_STRING};
    $env->{'psgix.harakiri.commit'} = $harakiri ? 1 : 0;

    return [200, [], [ $harakiri ? "We are about to destroy ourselves\n" : "We will live for another request\n" ]];
}
