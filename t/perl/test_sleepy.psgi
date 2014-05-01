use strict;
use warnings;
use Time::HiRes qw(usleep);

sub {
    my $env = shift;

    die "PANIC: We are expecting to support psgix.cleanup" unless $env->{'psgix.cleanup'};
    my $msleep = 2 * 1000 + int rand 7 * 1000; # 2..10ms
    my $csleep = 2 * 1000 + int rand 7 * 1000; # 2..10ms

    push @{$env->{'psgix.cleanup.handlers'}} => sub { usleep($csleep) };
    usleep($msleep);

    return [
        200,
        [],
        [ "Responding. Slept $msleep us in the main phase, sleeping $csleep us in the cleanup phase" ],
    ];
}
