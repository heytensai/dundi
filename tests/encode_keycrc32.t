#!/usr/bin/perl
$encoded = 'aaaabbbb00000010130a7a727470747074707470';
$packet = {
	'ie' => [
		{
			'type' => 'KEYCRC32',
			'keycrc32' => 'zrtptptptp',
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
