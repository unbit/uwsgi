use strict;
use warnings;

use FileHandle;
use IO::File;
use IO::String;

my $code = do { local ( @ARGV, $/ ) = __FILE__; <> };

sub ObjectPath::path { __FILE__ }

sub {
    my $path = shift->{PATH_INFO};

    my $body = $path eq '/Array'      ? [ split //, $code ]
             : $path eq '/Code'       ? sub {}
             : $path eq '/DATA'       ? \*DATA
             : $path eq '/DIRHANDLE'  ? do { opendir my $fh, '.'; $fh }
             : $path eq '/FILEHANDLE' ? do { open my $fh, __FILE__; $fh }
             : $path eq '/FileHandle' ? FileHandle->new(__FILE__)
             : $path eq '/Float'      ? 3.14
             : $path eq '/FloatRef'   ? \3.14
             : $path eq '/Format'     ? *STDOUT{FORMAT}
             : $path eq '/FormatRef'  ? \*STDOUT{FORMAT}
             : $path eq '/IO::File'   ? IO::File->new(__FILE__)
             : $path eq '/Hash'       ? { foo => 'bar' }
             : $path eq '/Int'        ? 3
             : $path eq '/IntRef'     ? \3
             : $path eq '/IO::String' ? IO::String->new($code)
             : $path eq '/Object'     ? bless({})
             : $path eq '/ObjectPath' ? bless( {}, 'ObjectPath' )
             : $path eq '/Regexp'     ? qr/foo/
             : $path eq '/String'     ? 'foo'
             : $path eq '/StringRef'  ? \'bar'
             : $path eq '/Undef'      ? undef
             : $path eq '/UndefRef'   ? \undef
             : return [ 404, [], [] ];

    [ 200, [ 'X-ref' => ref $body ], $body ];
};

__DATA__
data data data
