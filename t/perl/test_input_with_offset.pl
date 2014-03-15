#!/usr/bin/perl

#uwsgi --http-socket :9090 --psgi apps/input_with_offset.pl

use IO::Socket::INET;

my @tests;

my $base = 'one_two_three_four';

push @tests, ['-1', 'HELLO', 'one_two_three_fouHELLO'];
push @tests, ['-2', 'HELLO', 'one_two_three_foHELLO'];
push @tests, ['-2', 'HELLOHELLOHELLOTEST2TEST3', 'one_two_three_foHELLOHELLOHELLOTEST2TEST3'];
push @tests, ['-12', 'HELLOHELLOHELLOTEST2TEST3', 'one_twHELLOHELLOHELLOTEST2TEST3'];
push @tests, ['-22', 'HELLOHELLOHELLOTEST2TEST3', "HELLOHELLOHELLOTEST2TEST3"];
push @tests, ['-22', 'HELLO', "HELLOne_two_three_four"];
push @tests, ['-23', 'HELLO', "HELLOone_two_three_four"];
push @tests, ['-25', 'HELLO', "HELLO\0\0one_two_three_four"];
push @tests, ['1', 'HELLO', "oHELLOo_three_four"];
push @tests, ['3', 'HELLO', "oneHELLOthree_four"];
push @tests, ['30', 'HELLO', "one_two_three_four\0\0\0\0\0\0\0\0\0\0\0\0HELLO"];

@ARGV or die "You must provide a host to test on, e.g. localhost:8080";

foreach(@tests) {
        print "testing: offset(".$_->[0].") body(".$_->[1].")\n";
        my $req = "POST /?".$base." HTTP/1.0\r\nContent-Length: ".length($_->[1])."\r\nuWSGI-Offset: ".$_->[0]."\r\n\r\n".$_->[1];

        my $s = IO::Socket::INET->new(PeerAddr => $ARGV[0]) or die "PANIC: Unable to construct socket";
        $s->send($req);

        my $response = '';
        while(1) {
                $s->recv(my $buf, 4096);
                last unless length($buf);
                $response .= $buf;
        }
        $s->close;

	my $expected = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n".$_->[2]."\n";
        if ($response ne $expected) {
                print "TEST FOR offset(".$_->[0].") body(".$_->[1].") FAILED:\nEXPECTED\n---\n".$expected."\n---\nGOT\n---\n".$response."\n---\n";
                exit;
        }
}

print "test result: SUCCESS\n";
