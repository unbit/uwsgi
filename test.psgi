use strict;
use warnings;

my $app = sub {
      my $env = shift;
      #uwsgi::reload;
      return [
          '200',
          [ 'Content-Type' => 'text/plain' ],
          [ "Hello World\r\n", $env->{'REQUEST_URI'} ],
      ];
};
