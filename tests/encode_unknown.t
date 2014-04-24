#!/usr/bin/perl
$encoded = 'aaaabbbb000000100c01ff';
$packet = {
	'ie' => [
		{
			'type' => 'UNKNOWN',
			'unknown' => 255,
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
