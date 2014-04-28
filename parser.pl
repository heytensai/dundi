#!/usr/bin/perl
#
# sample Dundi.pm application
#
# Copyright (c) 2014 Corey Edwards <tensai@zmonkey.org>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use IO::Socket::INET;
use Data::Dumper;
use Dundi;

my $sock = IO::Socket::INET->new(LocalPort => 4520, Proto => 'udp', ReuseAddr => 1);

my $dundi = Dundi->new();

while (1){
	my $buffer;
	$sock->recv($buffer, 1024);
	my $peer_address = $sock->peerhost();
	my $peer_port = $sock->peerport();

	print "datagram received from $peer_address, $peer_port";
	print " len " . length($buffer);
	print "\n";

	#my ($hex) = unpack('H*', $buffer);
	#print "hex=$hex\n";

	my $packet = $dundi->parse($buffer);
	print Dumper($packet);
}

