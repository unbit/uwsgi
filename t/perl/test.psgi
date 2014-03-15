use strict;
use warnings;
BEGIN {
    die "PANIC: We should only load this once" if ++$main::count_BEGIN > 1;
}
die "PANIC: We should only run this once" if ++$main::count_runs > 1;

uwsgi::register_rpc('hello', sub {
	my ($one, $two, $three) = @_;
	unless($one) {
		return "passed no args to RPC func";
	}
	return $three.'-'.$two.'-'.$one;
});

my $rpc_value = uwsgi::call('hello', 'foo', 'bar', 'test');

if ($rpc_value) {
	print "rpc value = ".$rpc_value."\n";
}

my $one = sub {
	my $env = shift;
	sleep(1);
	print "one\n";
};

my $two = sub {
	my $env = shift;
	sleep(1);
	print "two\n";
};

my $four = sub {
	my $signum = shift;
	print "i am signal ".$signum."\n" ;
};

uwsgi::register_signal(17, '', $four);
uwsgi::register_signal(30, '', $two);

my $three = sub {
	my $env = shift;
	sleep(1);
	print "three\n";
};


uwsgi::postfork(sub {
	print "forked !!!\n";
});

uwsgi::atexit(sub {
	print "exited\n";
});

my $app = sub {
	my $env = shift;
	uwsgi::signal(17);
	uwsgi::signal(30);

	my ($package, $filename, $line) = caller;
	die "Expecting reasonable caller() return values, not [$package, $filename, $line]"
	    unless $package eq 'main' and $filename =~ /\btest\.psgi$/s and $line == 0;

	if ($env->{'psgix.cleanup'}) {
		print "cleanup supported\n";
		push @{$env->{'psgix.cleanup.handlers'}}, $one;
		push @{$env->{'psgix.cleanup.handlers'}}, $two;
		push @{$env->{'psgix.cleanup.handlers'}}, $three;
	}
	uwsgi::cache_set("key1", "val1");
	if ($rpc_value) {
		print uwsgi::call('hello')."\n";
	}
	print 'pid '.$$."\n";
	return [
          '200',
          [ 'Content-Type' => 'text/plain' ],
          [ "Hello World\r\n", $env->{'REQUEST_URI'}, uwsgi::cache_get('key1'), uwsgi::call('hello') ],
	];
};
