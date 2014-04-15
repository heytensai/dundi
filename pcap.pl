#!/usr/bin/perl
#
# sample Dundi.pm application

use strict;
use warnings;

use Data::Dumper;
use Getopt::Long;
use Net::Pcap;
use Dundi;

my %options = (
	dev => undef,
	promisc => 0,
	snaplen => 1500,
	bpf => 'udp and port 4520',
	strip => 88,
	bits => undef,
);
GetOptions(
	'dev=s' => \$options{dev},
	'promisc' => \$options{promisc},
	'snaplen=i' => \$options{snaplen},
	'bpf=s' => \$options{bpf},
	'strip=i' => \$options{strip},
	'bits' => \$options{bits},
);

my $dundi = Dundi->new();

my $err;
my $pcap = Net::Pcap::open_live($options{dev}, $options{snaplen}, $options{promisc}, 50, \$err);
if (!$pcap){
	print "error $err\n";
	exit 1;
}
my $bpf;
Net::Pcap::compile($pcap, \$bpf, $options{bpf}, 1, 0);
Net::Pcap::setfilter($pcap, $bpf);
Net::Pcap::loop($pcap, -1, \&process_packet, '');

sub process_packet
{
	my $user_data = shift;
	my $hdr = shift;
	my $buffer = shift;

	# naive way to strip off the IP/TCP headers.
	# this is probably highly prone to breakage.
	my $bits = unpack('H*', $buffer);
	if ($options{bits}){
		print "$bits\n";
	}
	$bits =~ s/^.{$options{strip}}//;
	$buffer = pack('H*', $bits);

	my $packet = $dundi->parse($buffer);
	print "DUNDi $packet->{cmd}\n";
	print " ($packet->{src}, $packet->{dst}) seq ($packet->{iseq}, $packet->{oseq})\n";
	print " (f=$packet->{f}, r=$packet->{r} flags=$packet->{flags})\n";
	print " Information Elements (", ($#{$packet->{ie}} + 1), ")\n";
	foreach my $ie (@{$packet->{ie}}){
		print "  " . $ie->{type} . "\n";
		foreach my $key (sort keys %{$ie}){
			next if ($key eq 'type');
			print "   $key=$ie->{$key}\n";
		}
	}
	print "\n";
}

