#!/usr/bin/perl
$encoded = 'aaaabbbb000000100b0204d2';
$packet = {
	'ie' => [
		{
			'type' => 'EXPIRATION',
			'expiration' => 1234,
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
