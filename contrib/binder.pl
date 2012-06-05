use POSIX;
use IO::Socket::INET;

my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 1717, Proto => 'tcp', Reuse => 1);
my $s2 = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 3022, Proto => 'tcp', Reuse => 1);

dup2($s->fileno, 17);
dup2($s2->fileno, 22);
exec './uwsgi','-M', '--socket','fd://17', '--http-socket','fd://22';
