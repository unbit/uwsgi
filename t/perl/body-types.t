use strict;
use warnings;

BEGIN {
    exec qw(
        ./uwsgi
        --disable-logging
        --http-socket :5000
        --perl-no-die-catch
        --perl-no-plack
        --psgi t/perl/apps/body-types.psgi
    ) unless my $pid = fork;

    END { kill 15, $pid }
}

use HTTP::Tiny;
use Test::More tests => 22;

my $http = HTTP::Tiny->new;
my $code = do { local ( @ARGV, $/ ) = 't/perl/apps/body-types.psgi'; <> };

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
