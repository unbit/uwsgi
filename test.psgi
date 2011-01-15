use strict;
use warnings;

print "rpc value = ".uwsgi::call('hello')."\n";

my $app = sub {
      my $env = shift;
      uwsgi::cache_set("key1", "val1");
      print uwsgi::call('hello');
      return [
          '200',
          [ 'Content-Type' => 'text/plain' ],
          [ "Hello World\r\n", $env->{'REQUEST_URI'}, uwsgi::cache_get('key1'), uwsgi::call('hello') ],
      ];
};
