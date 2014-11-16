#uwsgi --psgi t/perl/active_workers_signal.pl -s :3031 --perl-no-plack --timer "17 3" -p 8 --cheap --idle 10
my $handler = sub {
	print "hello i am the signal handler on worker ".uwsgi::worker_id()."\n";
};

uwsgi::register_signal(17, 'active-workers', $handler);

my $app = sub {
};

