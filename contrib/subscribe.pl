#!/usr/bin/perl

use IO::Socket::INET;

my %items = {};

$items{'key'} = $ARGV[1];
$items{'address'} = $ARGV[2];

my $uwsgi_pkt = '';

foreach(keys %items) {
	$uwsgi_pkt .= pack('v', length($_)).$_.pack('v', length($items{$_})).$items{$_};	
}

my $udp = new IO::Socket::INET(PeerAddr => $ARGV[0], Proto => 'udp');

$udp->send(pack('CvC', 224, length($uwsgi_pkt), 0).$uwsgi_pkt);

print ''.(length($uwsgi_pkt)+4).' bytes sent to '.$ARGV[0]."\n";
