#!/usr/bin/perl
$encoded = 'aaaabbbb000000100e1f025768617463686f6f2074616c6b696e272027626f75742057696c6c69733f';
$packet = {
	'ie' => [
		{
			'type' => 'CAUSE',
			'code' => 2,
			'description', "Whatchoo talkin' 'bout Willis?",
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
