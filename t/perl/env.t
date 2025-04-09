use strict;
use warnings;

use Config;
use HTTP::Tiny;
use Test::Deep;
use Test::More;

chomp( my $host = `hostname` );

my ( $t, $f ) = ( bool(1), bool(0) );

my $http = HTTP::Tiny->new;
my %exp  = (
    HTTP_HOST                => 'localhost:5000',
    HTTP_USER_AGENT          => $http->agent,
    PATH_INFO                => '/',
    QUERY_STRING             => '',
    REMOTE_ADDR              => '127.0.0.1',
    REQUEST_METHOD           => 'GET',
    REQUEST_URI              => '/',
    SCRIPT_NAME              => '',
    SERVER_NAME              => $host,
    SERVER_PORT              => 5000,
    SERVER_PROTOCOL          => 'HTTP/1.1',
    'psgi.errors'            => re(qr/^uwsgi::error=SCALAR\(0x[\da-f]+\)$/),
    'psgi.input'             => re(qr/^uwsgi::input=SCALAR\(0x[\da-f]+\)$/),
    'psgi.multiprocess'      => $f,
    'psgi.multithread'       => $f,
    'psgi.nonblocking'       => $f,
    'psgi.run_once'          => $f,
    'psgi.streaming'         => $t,
    'psgi.url_scheme'        => 'http',
    'psgi.version'           => re(qr/^ARRAY\(0x[\da-f]+\)$/),
    'psgix.cleanup'          => $t,
    'psgix.cleanup.handlers' => re(qr/^ARRAY\(0x[\da-f]+\)$/),
    'psgix.harakiri'         => $f,
    'psgix.input.buffered'   => $f,
    'psgix.logger'           => re(qr/^CODE\(0x[\da-f]+\)$/),
);

my @tests = (
    [ 'Defaults', {} ],
    [ 'Master', { 'psgix.harakiri' => $t }, '--master' ],
    [ 'Async', { 'psgi.nonblocking' => $t }, '--async' => 1 ],
    [
        'Workers',
        { 'psgix.harakiri' => $t, 'psgi.multiprocess' => $t },
        '--master', '--workers' => 2,
    ],
);

push @tests, [ 'Threads', { 'psgi.multithread' => $t }, '--threads' => 2 ]
    if $ENV{UWSGI_PERL} =~ /-thread$/;

plan tests => scalar @tests;

for (@tests) {
    my ( $name, $exp, @opts ) = @$_;

    exec qw(
        ./uwsgi
        --disable-logging
        --http-socket :5000
        --perl-no-die-catch
        --perl-no-plack
        --psgi t/perl/apps/env.psgi
    ), @opts unless my $pid = fork;

    sleep 1;    # Let uWSGI start.

    my %got = split /\n/, $http->get('http://localhost:5000')->{content};

    cmp_deeply \%got, { %exp, %$exp }, $name;

    kill 15, $pid;

    sleep 1;    # Let uWSGI kill it's workers.
}
