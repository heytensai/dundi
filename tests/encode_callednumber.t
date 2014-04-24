#!/usr/bin/perl
$encoded = 'aaaabbbb00000010030735353531323334';
$packet = {
	'ie' => [
		{
			'type' => 'CALLEDNUMBER',
			'number' => '5551234',
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
