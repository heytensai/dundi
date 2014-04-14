#!/usr/bin/perl
#
# sample Dundi.pm application

use strict;
use warnings;

use IO::Socket::INET;
use Data::Dumper;
use Dundi;

# TODO use pcap instead
my $sock = IO::Socket::INET->new(LocalPort => 4521, Proto => 'udp', ReuseAddr => 1);

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

