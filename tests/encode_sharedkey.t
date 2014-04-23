#!/usr/bin/perl
$encoded = 'aaaabbbb00000010110712131415182228';
$packet = {
	'ie' => [
		{
			'type' => 'SHAREDKEY',
			'key' => "\x12\x13\x14\x15\x18\x22\x28",
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
