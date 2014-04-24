#!/usr/bin/perl
$encoded = 'aaaabbbb00000010020470726976';
$packet = {
	'ie' => [
		{
			'type' => 'CALLEDCONTEXT',
			'context' => 'priv',
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
