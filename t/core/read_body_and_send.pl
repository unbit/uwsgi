#!/usr/bin/perl

#uwsgi --http-socket :9090 --psgi t/core/apps/read_body_and_send.pl

use IO::Socket::INET;

my @chars = ("A".."Z", "a".."z");

foreach(0..100) {
	$size = int(rand(8*1024*1024));
	print "testing: round ".$_." body size ".$size."\n";
	my $req = "POST /foobar HTTP/1.0\r\n";
	$req .= 'Content-Length: '.$size."\r\n\r\n";
	my $body = '';
	$body .= $chars[rand @chars] for 1..($size);
	$req .= $body;

	my $s = IO::Socket::INET->new(PeerAddr => $ARGV[0]);
	$s->send($req);

	my $response = '';
	while(1) {
		$s->recv(my $buf, 4096);
		last unless length($buf);
		$response .= $buf;
	}
	$s->close;

	if ($response ne "HTTP/1.0 200 OK\r\nContent-Type: x-application/binary\r\n\r\n".$body) {
		print "TEST FOR ROUND ".$_." FAILED\n";
		exit;
	}
}

print "test result: SUCCESS\n";
