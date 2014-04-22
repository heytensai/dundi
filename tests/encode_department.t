#!/usr/bin/perl
$encoded = 'aaaabbbb00000010150d4d79204465706172746d656e74';
$packet = {
	'ie' => [
		{
			'type' => 'DEPARTMENT',
			'department' => 'My Department',
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
