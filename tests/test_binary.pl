#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Dundi;

my $dundi = Dundi->new();

my $encoded;
my $packet;

while (my $test = shift){
	print "running test $test\n";

	local $/ = undef;
	open(my $fh, '<', 'tests/' . $test . '.t');
	binmode $fh;
	my $t = <$fh>;
	close($fh);

	eval $t;

	my $stream = $dundi->encode($packet);

	if ($stream eq 1 || $stream eq 2){
		print "error $stream while encoding\n";
	}
	else{
		print "  $encoded\n";
		my $unpacked = unpack('H*', $stream);
		print "  $unpacked\n";
		if ($encoded eq $unpacked){
			print "match\n";
		}
	}
}
