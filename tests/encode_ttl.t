#!/usr/bin/perl
$encoded = 'aaaabbbb0000001006020020';
$packet = {
	'ie' => [
		{
			'type' => 'TTL',
			'ttl' => 32,
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
