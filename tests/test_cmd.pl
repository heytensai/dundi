#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Dundi;

my $dundi = Dundi->new();

my $stream = 'aaaabbbb00000010140a00077470747074707470';

$stream = pack('H*', $stream);

my $ie = $dundi->parse($stream);
print Dumper($ie);
