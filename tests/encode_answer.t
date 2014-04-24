#!/usr/bin/perl
$encoded = 'aaaabbbb000000100512123456abcdef020045000a5349502f666f6f';
$packet = {
	'ie' => [
		{
			'type' => 'ANSWER',
			'protocol' => 'SIP',
			'exists' => 1,
			'canmatch' => 1,
			'mobile' => 1,
			'residential' => 0,
			'eid' => '123456abcdef',
			'weight' => 10,
			'destination' => 'SIP/foo',
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
