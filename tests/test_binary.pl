#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Dundi;

my $dundi = Dundi->new();

# should encode to 'aaaabbbb00000010140a00077470747074707470'
my $encoded = 'aaaabbbb00000010130a7a727470747074707470';
my $packet = {
	'ie' => [
		{
			'type' => 'KEYCRC32',
			'keycrc32' => 'zrtptptptp',
		},
	],
	'cmd' => 'ACK',
	'flags' => 16,
	'r' => 0,
	'iseq' => 0,
	'oseq' => 0,
	'src' => 43690,
	'f' => 0,
	'dst' => 48059,
};

my $stream = $dundi->encode($packet);

if ($stream eq 1 || $stream eq 2){
	print "error $stream while encoding\n";
}
else{
	print "$encoded\n";
	print unpack('H*', $stream);
	print "\n";
}
