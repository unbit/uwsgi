#!/usr/bin/perl

#uwsgi --http-socket :9090 --route-run "send:\${PATH_INFO}"

use IO::Socket::INET;

my @tests;

push @tests, ['/foo','/foo'];
push @tests, ['./foo','/foo'];
push @tests, ['./foo/bar?a=1','/foo/bar'];
push @tests, ['//foo/bar','//foo/bar'];
push @tests, ['foo/bar','foo/bar'];
push @tests, ['foo/bar/../','foo/'];
push @tests, ['foo/bar/..','foo/'];
push @tests, ['/foo/bar/..','/foo/'];
push @tests, ['../../../foo/bar/..','/foo/'];
push @tests, ['test1/test2/../test3/','test1/test3/'];
push @tests, ['t#est1/test2/../test3/','t'];
push @tests, ['/one/two/three/four/../five','/one/two/three/five'];
push @tests, ['/one/two/three/four/../../five','/one/two/five'];
push @tests, ['/one/two/three/four/../../five/','/one/two/five/'];
push @tests, ['/one/two/three/four/../../five/..','/one/two/'];
push @tests, ['.one/two/three/four/../../five/..','.one/two/'];
push @tests, ['..one/two/three/four/../../five/..','..one/two/'];
push @tests, ['/../','/'];
push @tests, ['../','/'];
push @tests, ['/.','/'];
push @tests, ['..one/two/three/four/../../../../../five/..','/'];
push @tests, ['./foo/.bar.','/foo/.bar.'];

foreach(@tests) {
	print "testing: ".$_->[0]."\n";
	my $req = "GET ".$_->[0]." HTTP/1.0\r\n\r\n";

	my $s = IO::Socket::INET->new(PeerAddr => $ARGV[0]);
	$s->send($req);

	my $response = '';
	while(1) {
		$s->recv(my $buf, 4096);
		last unless length($buf);
		$response .= $buf;
	}
	$s->close;

	if ($response ne $_->[1]) {
		print "TEST FOR ".$_->[0]." FAILED: EXPECTED ".$_->[1]." GOT ".$response."\n";
		exit;
	}
}

print "test result: SUCCESS\n";
