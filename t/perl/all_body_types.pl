#!/usr/bin/env perl

use strict;
use warnings;

use HTTP::Tiny;
use Test::More;

my $pid;
my $cpus = `nproc`;
my $http = HTTP::Tiny->new;
my $code = do { local ( @ARGV, $/ ) = 't/perl/apps/all_body_types.psgi'; <> };

# Incase we die before we're able to stop uWSGI.
END { kill 15, $pid if $pid }

for my $perl ( qw/5.20.2 5.18.4 5.16.3 5.14.4 5.12.4 5.10.1 5.8.9/ ) {
    for my $thread (0, 1) {
        my $name = 'uwsgi-perl-' . $perl . ( '-thread' x $thread );

        system 'perlbrew', 'install', $perl,
            '--as', $name, '-D', 'useshrplib', '-j', $cpus, '-n', '--noman',
            ('--thread') x $thread;

        # Ensure all deps of t/perl/apps/all_body_types.psgi are installed.
        system 'perlbrew', 'exec', '--with', $name,
            'cpanm', '-n', 'IO::String' and die $!;

        system 'python', 'uwsgiconfig.py', '-c' and die $!;

        system 'perlbrew', 'exec', '--with', $name,
            'python', 'uwsgiconfig.py', '-b', 'plonly' and die $!;

        exec qw(
            ./uwsgi
            --http-socket :5000
            --perl-no-die-catch
            --perl-no-plack
            --psgi t/perl/apps/all_body_types.psgi
        ) unless $pid = fork;

        # Give uWSGI a chance to start.
        sleep 1;

        subtest $name => sub {
            for (
                [ Array        => 1, 'ARRAY'      ],
                [ Code         => 0, 'CODE'       ],
                [ DATA         => 1, 'GLOB'       ],
                [ DIRHANDLE    => 0, 'GLOB'       ],
                [ FILEHANDLE   => 1, 'GLOB'       ],
                [ FileHandle   => 1, 'FileHandle' ],
                [ Float        => 0, ''           ],
                [ FloatRef     => 0, 'SCALAR'     ],
                [ Format       => 0, ''           ],
                [ FormatRef    => 0, 'SCALAR'     ],
                [ Hash         => 0, 'HASH'       ],
                [ Int          => 0, ''           ],
                [ IntRef       => 0, 'SCALAR'     ],
                [ 'IO::File'   => 1, 'IO::File'   ],
                [ 'IO::String' => 1, 'IO::String' ],
                [ Object       => 0, 'main'       ],
                [ ObjectPath   => 1, 'ObjectPath' ],
                [ Regexp       => 0, 'Regexp'     ],
                [ String       => 0, ''           ],
                [ StringRef    => 0, 'SCALAR'     ],
                [ Undef        => 0, ''           ],
                [ UndefRef     => 0, 'SCALAR'     ],
            ) {
                my ( $path, $has_content, $ref ) = @$_;

                my $got = $http->get( 'http://localhost:5000/' . $path );

                delete @$got{qw/protocol reason success status url/};

                is_deeply $got, {
                    content => $code x $has_content,
                    headers => { 'x-ref' => $ref },
                }, $path;
            }
        };

        kill 15, $pid;
    }
}

done_testing;
