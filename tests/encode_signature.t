#!/usr/bin/perl
$encoded = 'aaaabbbb00000010120412131415';
$packet = {
	'ie' => [
		{
			'type' => 'SIGNATURE',
			'signature' => "\x12\x13\x14\x15",
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
