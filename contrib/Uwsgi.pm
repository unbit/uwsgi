package Plack::Handler::Uwsgi;

use strict;
use warnings;

use IO::Socket::INET;
use HTTP::Status;

use Plack::Util;

sub new {
    my $class = shift;
    my $self  = bless {@_}, $class;
    $self;
}

sub run {
    my ($self, $app) = @_;

    my $server;

    if (exists($ENV{'UWSGI_FD'})) {
        $server = IO::Socket::UNIX->new_from_fd($ENV{'UWSGI_FD'}, '+<');
    }
    else {	
        $server = IO::Socket::INET->new(LocalPort => $self->{port}, LocalAddr => $self->{host}, Listen => 100, ReuseAddr => 1);
    }

    while ( my $client = $server->accept ) {

        my $head = '';
        my $remains = 4;

        while($remains) {
            $client->recv(my $buf, $remains);	
            last unless $buf;
            $head.=$buf;
            $remains -= length($buf);
        }

        if (length($head) != 4) {
            $client->close;
            next;
        }

        my ($mod1, $envsize, $mod2) = unpack('CvC', $head);

        unless ($envsize) {
            $client->close;
            next;
        }

        $remains = $envsize;
        my $envbuf = '';
        while($remains) {
            my $buf;
            if ($remains >= 4096) {
                $client->recv($buf, 4096);	
            }
            else {
                $client->recv($buf, $remains);	
            }

            unless($buf) {
                $client->close;
                next;
            }

            $envbuf.=$buf;
            $remains -= length($buf);
        }

        if (length($envbuf) != $envsize ) {
            $client->close;
            next;
        }

        my %env;

        my $i = 0;
        while($i < $envsize) {
            my $kl = unpack('v', substr($envbuf, $i, 2)); $i+=2;
            my $key = substr($envbuf, $i, $kl); $i+=$kl;
            my $vl = unpack('v', substr($envbuf, $i, 2)); $i+=2;
            $env{$key} = substr($envbuf, $i, $vl); $i+=$vl;
        }

        my $env = {
            %env,
            'psgi.version'      => [1,1],
            'psgi.url_scheme'   => ($env{HTTPS}||'off') =~ /^(?:on|1)$/i ? 'https' : 'http',
            'psgi.input'        => $client,
            'psgi.errors'       => *STDERR,
            'psgi.multithread'  => Plack::Util::FALSE,
            'psgi.multiprocess' => Plack::Util::TRUE,
            'psgi.run_once'     => Plack::Util::FALSE,
            'psgi.streaming'    => Plack::Util::TRUE,
            'psgi.nonblocking'  => Plack::Util::FALSE,
        };

        my $res = Plack::Util::run_app $app, $env;

        if (ref $res eq 'ARRAY') {
            $self->_handle_response($client, $env{'SERVER_PROTOCOL'}, $res);
        }
        elsif (ref $res eq 'CODE') {
            $res->(sub {
                    $self->_handle_response($client, $env{'SERVER_PROTOCOL'}, $_[0]);
                });
        }
        else {
            die "Bad response $res";
        }

        $client->close;

    }
}

sub _handle_response {
    my ($self, $client, $protocol, $res) = @_;

    $client->send($protocol.' '.$res->[0].' '.HTTP::Status::status_message( $res->[0] )."\r\n");

    my $headers = $res->[1];
    my $hdrs = '';
    while (my ($k, $v) = splice @$headers, 0, 2) {
        $hdrs .= "$k: $v\r\n";
    }
    $hdrs .= "\r\n";

    $client->send($hdrs);

    my $cb = sub { $client->send($_[0]) };
    my $body = $res->[2];
    if (defined $body) {
        Plack::Util::foreach($body, $cb);
    }
    else {
        return Plack::Util::inline_object write => $cb,close => sub { };
    }
}

1;
