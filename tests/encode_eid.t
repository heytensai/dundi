#!/usr/bin/perl
$encoded = 'aaaabbbb000000100106112233aabbcc';
$packet = {
	'ie' => [
		{
			'type' => 'EID',
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
