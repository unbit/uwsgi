#!/usr/bin/perl

use Crypt::OpenSSL::RSA;
use IO::Socket::INET;

open PK,$ARGV[3];
my @lines = <PK>;
close PK;

$rsa_priv = Crypt::OpenSSL::RSA->new_private_key(join('',@lines));

my %items = {};

$items{'key'} = $ARGV[1];
$items{'address'} = $ARGV[2];

my $uwsgi_pkt = '';

foreach(keys %items) {
	$uwsgi_pkt .= pack('v', length($_)).$_.pack('v', length($items{$_})).$items{$_};	
}

my $unix_check = time();

$uwsgi_pkt .= pack('v', 4).'unix'.pack('v', length($unix_check)).$unix_check;

my $signature = $rsa_priv->sign($uwsgi_pkt);

$uwsgi_pkt .= pack('v', 4).'sign'.pack('v', length($signature)).$signature;


my $udp = new IO::Socket::INET(PeerAddr => $ARGV[0], Proto => 'udp');

$udp->send(pack('CvC', 224, length($uwsgi_pkt), 0).$uwsgi_pkt);

print ''.(length($uwsgi_pkt)+4).' bytes sent to '.$ARGV[0]."\n";
