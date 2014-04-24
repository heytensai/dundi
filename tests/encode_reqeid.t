#!/usr/bin/perl
$encoded = 'aaaabbbb000000100f06aabbcc112233';
$packet = {
	'ie' => [
		{
			'type' => 'REQEID',
			'id' => 'aabbcc112233',
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
