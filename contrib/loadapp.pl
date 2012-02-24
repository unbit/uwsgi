use IO::Socket::INET;

my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $ARGV[0]);

my $mountpoint = $ARGV[1];
my $app = $ARGV[2];

my $uwsgi_appid = pack('v', length('UWSGI_APPID')).'UWSGI_APPID'.pack('v', length($mountpoint)).$mountpoint;
my $uwsgi_script = pack('v', length('UWSGI_SCRIPT')).'UWSGI_SCRIPT'.pack('v', length($app)).$app;

$s->send(pack('CvC', 5, length($uwsgi_appid.$uwsgi_script),0).$uwsgi_appid.$uwsgi_script);

while((my $cnt = $s->recv(my $buf, 4096))> 0) {
	print $buf;
}
