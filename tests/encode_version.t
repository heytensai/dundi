#!/usr/bin/perl
$encoded = 'aaaabbbb000000100a020001';
$packet = {
	'ie' => [
		{
			'type' => 'VERSION',
			'version' => 1,
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
