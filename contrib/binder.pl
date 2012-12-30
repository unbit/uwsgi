use POSIX;
use IO::Socket::INET;
use IO::Socket::INET6;
use IO::Socket::UNIX;

my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 1717, Proto => 'tcp', Reuse => 1);
my $s2 = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 3022, Proto => 'tcp', Reuse => 1);
my $s3 = IO::Socket::INET6->new(LocalAddr => '::', LocalPort => 3017, Proto => 'tcp', Reuse => 1);
my $s4 = IO::Socket::UNIX->new(Local => '/tmp/u.sock', Listen => 1);

dup2($s->fileno, 17);
dup2($s2->fileno, 22);
dup2($s3->fileno, 30);
dup2($s4->fileno, 0);
exec './uwsgi','-M', '--socket','fd://17', '--http-socket','fd://22', '--socket','fd://30','--stats',':5001';
