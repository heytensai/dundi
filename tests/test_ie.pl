#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Dundi;

my $dundi = Dundi->new();

# should decode to
# VERSION=1
# EIDDIRECT=f23c91db245c
# CALLEDNUMBER=
# CALLEDCONTEXT=
# TTL=32
my $stream = '0a0200011704726172611604726172610406f23c91db245c0303323030020470726976060200200e2403556e656e6372797074656420726573706f6e736573206e6f74207065726d6974746564';
$stream = pack('H*', $stream);

my $ie = $dundi->parse_ie('', $stream);
print Dumper($ie);
