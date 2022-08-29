use strict;
use warnings;

sub {
    my $env = shift;

    my $cl = $env->{CONTENT_LENGTH};
    $env->{'psgi.input'}->seek(0,0);
    my $content = '';
    while ($cl) {
        $env->{'psgi.input'}->read(my $chunk, $cl < 8192 ? $cl : 8192);
        my $read = length $chunk;
        $cl -= $read;
        $content .= $chunk;
    }

    return [200, [], [ "Your content was: <$content>" ]];
};

__END__

This is a trivial test that prints out a POST request, it's here to
test a regression introduced in 2.0-103-gf041d10 where doing reads
without offsets, e.g.:

    $ http_proxy= curl -d '{ "what": "ever" }' http://localhost:8080/
    Your content was: $VAR1 = '{ "what": "ever" }';

Would result in:

    Use of uninitialized value in subroutine entry at
    /home/v-perlbrew/perl5/perlbrew/perls/perl-5.19.6/lib/site_perl/5.19.6/Plack/Request.pm
    line 280.

Which is due to this commit having a one-off error in counting stack
items.

    $ git bisect good
    f041d1095ddf7541c4b275e16d2ed3355a8e2be9 is the first bad commit
    commit f041d1095ddf7541c4b275e16d2ed3355a8e2be9
    Author: Unbit <info@unbit.it>
    Date:   Wed Feb 5 11:21:01 2014 +0100

        perl refactoring

    :040000 040000 98a25406b7edb9bd0b9be8bbcd351a99e7ce2d33 0087e3ca4b6bd65a087fade65d43a56085298ef0 M      plugins

