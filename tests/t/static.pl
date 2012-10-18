use IO::Socket::INET;
use Digest::MD5 qw(md5) ;

$NUM = 50;

my @commands;

push @commands, "./uwsgi --http-socket :9191 --disable-logging --static-offload-to-thread 64 --static-map /foobar=./t_foobar.txt --pidfile ./t_foobar.pid &";
push @commands, "./uwsgi --http-socket :9191 --disable-logging -M -p 4 --static-offload-to-thread 64 --static-map /foobar=./t_foobar.txt --pidfile ./t_foobar.pid &";
push @commands, "./uwsgi --http :9191 --disable-logging --static-map /foobar=./t_foobar.txt --static-offload-to-thread 64 --pidfile ./t_foobar.pid &";

print "generating random data for the test...\n";

my $content = generate_random_content(1024*1024);
my $first_digest = md5($content);

open FOOBAR,'>t_foobar.txt';
print FOOBAR $content;
close FOOBAR;

foreach my $cmd(@commands) {

	system $cmd;
	sleep(1);


	my @s;

	print "sending requests to uWSGI...\n";

	for(my $i=0;$i<$NUM;$i++) {
		$s[$i] = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 9191);	
		$s[$i]->send("GET /foobar HTTP/1.0\r\nHost: 127.0.0.1:9191\r\n\r\n");
	}

	my @body;

	print "receiving responses from uWSGI...\n";

	while(1) {
		$end = 0;
		for(my $i=0;$i<$NUM;$i++) {
			$s[$i]->recv(my $buf, 32768);
			$end++ unless $buf;
			$body[$i].=$buf;
		}
		last if $end >= $NUM;
	}

	print "checking uWSGI responses...\n";

	foreach my $data (@body) {
		$data =~ s/^(.|\n|\r)*\r\n\r\n//m;
		if (md5($data) ne $first_digest) {
			end_test("md5 does not match");
		}
	}

	system('kill -INT `cat t_foobar.pid`');

	sleep(3);
}

print "TEST PASSED\n";

sub generate_random_content {
	my $size = shift;
	my @chars=('a'..'z','A'..'Z','0'..'9');
	my $random_string = '';
	foreach (1..$size) {
		$random_string.=$chars[rand @chars];
	}

	return $random_string;
}

sub end_test {
	my $msg = shift;
	print 'TEST FAILED: '.$msg."\n";
	system('kill -INT `cat t_foobar.pid`');
	exit;
}
