use v5.10.0;
use strict;
use warnings;
use Time::HiRes qw(sleep);
use autodie qw(:all);

my $psgi = $ARGV[0] || 't/perl/test_hello.psgi';

for my $use_thunder_lock (0,1) {
    for my $cpu_multiplier (1,2,4,8,16,32,64) {
        my $procs = 16 * $cpu_multiplier;
        my $desc = sprintf "%3d procs %2s/TL", $procs, ($use_thunder_lock ? "w" : "wo");
        my $tl_cl = $use_thunder_lock ? "--thunder-lock --lock-engine ipcsem --ftok $psgi" : "";

        #say STDERR "Now testing $desc";
        system q[for p in $(ps auxf|grep uwsgi.*--disable-logging|grep -v grep|awk '{print $2}'); do kill $p; done];
        system qq[./uwsgi --http 127.0.0.1:8080 --processes $procs --psgi $psgi --disable-logging $tl_cl >/dev/null 2>&1 &];
        sleep 0.5;
        chomp(my $ab = qx[http_proxy= ab -n 10000 -c 32 http://localhost:8080/ 2>&1]);
        my ($seconds) = $ab =~ m[Time taken for tests:\s+([0-9.]+) seconds];
        say STDERR "$seconds\t$desc";
        system q[for p in $(ps auxf|grep uwsgi.*--disable-logging|grep -v grep|awk '{print $2}'); do kill $p; done];
        sleep 0.5;
    }
}

__END__
$ perl t/perl/test_benchmark.pl t/perl/test_sleepy.psgi
7.128    16 procs wo/TL
3.547    32 procs wo/TL
2.038    64 procs wo/TL
2.880   128 procs wo/TL
4.578   256 procs wo/TL
8.199   512 procs wo/TL
13.379  1024 procs wo/TL
7.123    16 procs  w/TL
3.559    32 procs  w/TL
2.036    64 procs  w/TL
1.972   128 procs  w/TL
2.026   256 procs  w/TL
2.172   512 procs  w/TL
2.412   1024 procs  w/TL

$ perl t/perl/test_benchmark.pl t/perl/test_hello.psgi
1.392    16 procs wo/TL
1.743    32 procs wo/TL
2.374    64 procs wo/TL
3.530   128 procs wo/TL
4.984   256 procs wo/TL
8.258   512 procs wo/TL
9.343   1024 procs wo/TL
1.134    16 procs  w/TL
1.284    32 procs  w/TL
1.152    64 procs  w/TL
1.084   128 procs  w/TL
1.286   256 procs  w/TL
1.559   512 procs  w/TL
1.537   1024 procs  w/TL
