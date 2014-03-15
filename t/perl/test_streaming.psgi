use strict;
use warnings;

sub {
	my $env = shift;

	return sub {
		my $responder = shift;
		my $writer = $responder->([ 200, [ 'Content-Type', 'text/plain' ]]);
		sleep 3;
		$writer->write("hello\n");
		sleep 3;
		$writer->write("world\n");
		$writer->close;
		return;
	};
}

__END__

Making a request to this will give you:

    $ date; curl -s -N -D - 'http://localhost:8080'
    Sat Mar 15 14:08:25 UTC 2014
    HTTP/1.1 200 OK
    Content-Type: text/plain

    hello
    world

And monitoring it with tcpflow shows how the output (including
headers) is flushed right away:

    $ sudo tcpflow -i lo -c port 8080 | perl -pe 's/^/localtime . " "/ge'
    Sat Mar 15 14:09:08 2014 127.000.000.001.55058-127.000.000.001.08080: GET / HTTP/1.1
    Sat Mar 15 14:09:08 2014 User-Agent: curl/7.35.0
    Sat Mar 15 14:09:08 2014 Host: localhost:8080
    Sat Mar 15 14:09:08 2014 Accept: */*
    Sat Mar 15 14:09:08 2014 
    Sat Mar 15 14:09:08 2014 
    Sat Mar 15 14:09:08 2014 127.000.000.001.08080-127.000.000.001.55058: HTTP/1.1 200 OK
    Sat Mar 15 14:09:08 2014 Content-Type: text/plain
    Sat Mar 15 14:09:08 2014 
    Sat Mar 15 14:09:08 2014 
    Sat Mar 15 14:09:11 2014 127.000.000.001.08080-127.000.000.001.55058: hello
    Sat Mar 15 14:09:11 2014 
    Sat Mar 15 14:09:14 2014 127.000.000.001.08080-127.000.000.001.55058: world
    Sat Mar 15 14:09:14 2014 
