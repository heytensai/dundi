#!/usr/bin/perl
$encoded = 'aaaabbbb0000001014050003666f6f';
$packet = {
	'ie' => [
		{
			'type' => 'HINT',
			'hint' => 'foo',
			'dontask' => 1,
			'ttlexpired' => 'true',
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
