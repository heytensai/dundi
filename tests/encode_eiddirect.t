#!/usr/bin/perl
$encoded = 'aaaabbbb000000100406112233aabbcc';
$packet = {
	'ie' => [
		{
			'type' => 'EIDDIRECT',
			'id' => '112233aabbcc',
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
