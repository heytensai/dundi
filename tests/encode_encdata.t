#!/usr/bin/perl
$encoded = 'aaaabbbb00000010102a000102030405060708090a0b0c0d0e0f6162636465666768696a6b6c6d6e6f707172737475767778797a';
$packet = {
	'ie' => [
		{
			'type' => 'ENCDATA',
			'iv' => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
			'encdata' => 'abcdefghijklmnopqrstuvwxyz',
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
