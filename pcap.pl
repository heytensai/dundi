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
);
GetOptions(
	'dev=s' => \$options{dev},
	'promisc' => \$options{promisc},
	'snaplen=i' => \$options{snaplen},
	'bpf=s' => \$options{bpf},
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
	$bits =~ s/^.{88}//;
	$buffer = pack('H*', $bits);

	my $packet = $dundi->parse($buffer);
	print Dumper($packet);
}

