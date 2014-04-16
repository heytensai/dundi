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
#my $stream = '0a0200011704726172611604726172610406f23c91db245c0303323030020470726976060200200e2403556e656e6372797074656420726573706f6e736573206e6f74207065726d6974746564';

# should decode to
# EID=f23c91db245c
# KEYCRC32
# ENCDATA
#my $stream = '0106f23c91db245c13043053e37e1040e6407a2374d2b64ae2bc2944a15a0a548208bdf5b2f902b54853940f4c11cdc9054fea8395dd793597d15e90f1d5821367f2a95568c142b4b5dded761d9fb9ad';

# should decode to
# HINT
my $stream = '140a00077470747074707470';

$stream = pack('H*', $stream);

my $ie = $dundi->parse_ie('', $stream);
print Dumper($ie);
