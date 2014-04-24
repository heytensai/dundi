# Dundi.pm
#
# Copyright (c) 2014 Corey Edwards <tensai@zmonkey.org>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Dundi;

use strict;
use warnings;
use threads;

require Carp;
use Data::Types;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
	new
	parse
	encode
);
our $VERSION = '0.1';

=head1 NAME

Dundi - A DUNDi library for Perl

=head1 SYNOPSIS

You know, DUNDi stuff but for Perl

=head1 DESCRIPTION

C<Dundi> is cool

=cut

my %CAUSE_NAME = (
	0x00 => 'Success',
	0x01 => 'General',
	0x02 => 'Reserved',
	0x03 => 'NoAuth',
	0x04 => 'Duplicate',
	0x05 => 'TTLExpired',
	0x06 => 'NeedKey',
	0x07 => 'BadEncrypt',
);

my %PROTOCOL = (
	'NONE' => 0x00,
	'IAX' => 0x01,
	'IAX2' => 0x01,
	'SIP' => 0x02,
	'H.323' => 0x03,
);

my %PROTOCOL_NAME = (
	$PROTOCOL{'NONE'} => 'NONE',
	$PROTOCOL{'IAX'} => 'IAX',
	$PROTOCOL{'SIP'} => 'SIP',
	$PROTOCOL{'H.323'} => 'H.323',
);

my %CMD = (
	'ACK' => 0x00,
	'DPDISCOVER' => 0x01,
	'DPRESPONSE' => 0x02,
	'EIDQUERY' => 0x03,
	'EIDRESPONSE' => 0x04,
	'INVALID' => 0x07,
	'UNKNOWN' => 0x08,
	'NULL' => 0x09,
	'REGREQ' => 0x0a,
	'REGRESPONSE' => 0x0b,
	'CANCEL' => 0x0c,
	'ENCRYPT' => 0x0d,
	'ENCREJ' => 0x0e,
);

my %CMD_NAME = (
	$CMD{ACK} => 'ACK',
	$CMD{DPDISCOVER} => 'DPDISCOVER',
	$CMD{DPRESPONSE} => 'DPRESPONSE',
	$CMD{EIDQUERY} => 'EIDQUERY',
	$CMD{EIDRESPONSE} => 'EIDRESPONSE',
	$CMD{INVALID} => 'INVALID',
	$CMD{UNKNOWN} => 'UNKNOWN',
	$CMD{NULL} => 'NULL',
	$CMD{REGREQ} => 'REGREQ',
	$CMD{REGRESPONSE} => 'REGRESPONSE',
	$CMD{CANCEL} => 'CANCEL',
	$CMD{ENCRYPT} => 'ENCRYPT',
	$CMD{ENCREJ} => 'ENCREJ',
);

my %IE = (
	'EID' => 0x01,
	'CALLEDCONTEXT' => 0x02,
	'CALLEDNUMBER' => 0x03,
	'EIDDIRECT' => 0x04,
	'ANSWER' => 0x05,
	'TTL' => 0x06,
	'VERSION' => 0x0a,
	'EXPIRATION' => 0x0b,
	'UNKNOWN' => 0x0c,
	'CAUSE' => 0x0e,
	'REQEID' => 0x0f,
	'ENCDATA' => 0x10,
	'SHAREDKEY' => 0x11,
	'SIGNATURE' => 0x12,
	'KEYCRC32' => 0x13,
	'HINT' => 0x14,
	'DEPARTMENT' => 0x15,
	'ORGANIZATION' => 0x16,
	'LOCALITY' => 0x17,
	'STATEPROV' => 0x18,
	'COUNTRY' => 0x19,
	'EMAIL' => 0x1a,
	'PHONE' => 0x1b,
	'IPADDR' => 0x1c,
);

my %IE_NAME = (
	$IE{EID} => 'EID',
	$IE{CALLEDCONTEXT} => 'CALLEDCONTEXT',
	$IE{CALLEDNUMBER} => 'CALLEDNUMBER',
	$IE{EIDDIRECT} => 'EIDDIRECT',
	$IE{ANSWER} => 'ANSWER',
	$IE{TTL} => 'TTL',
	$IE{VERSION} => 'VERSION',
	$IE{EXPIRATION} => 'EXPIRATION',
	$IE{UNKNOWN} => 'UNKNOWN',
	$IE{CAUSE} => 'CAUSE',
	$IE{REQEID} => 'REQEID',
	$IE{ENCDATA} => 'ENCDATA',
	$IE{SHAREDKEY} => 'SHAREDKEY',
	$IE{SIGNATURE} => 'SIGNATURE',
	$IE{KEYCRC32} => 'KEYCRC32',
	$IE{HINT} => 'HINT',
	$IE{DEPARTMENT} => 'DEPARTMENT',
	$IE{ORGANIZATION} => 'ORGANIZATION',
	$IE{LOCALITY} => 'LOCALITY',
	$IE{STATEPROV} => 'STATEPROV',
	$IE{COUNTRY} => 'COUNTRY',
	$IE{EMAIL} => 'EMAIL',
	$IE{PHONE} => 'PHONE',
	$IE{IPADDR} => 'IPADDR',
);

sub new
{
	my $class = shift;
	my $self = {};

	return bless $self, $class;
}

sub parse
{
	my $self = shift;
	my $buffer = shift;
	my $packet = {};

	# DEBUG
	#my $hex = unpack('H*', $buffer);
	#print "hex=$hex\n";

	my ($src_tnx, $dst_tnx, $iseq, $oseq, $fld, $flags) = unpack('nnCCCC', $buffer);
	my $f = ($fld & 0x80) >> 7;
	my $r = ($fld & 0x40) >> 7;
	my $cmd = ($fld & 0x3f);

	# if it's a command we recognize
	if (defined $CMD_NAME{$cmd}) {
		$packet->{cmd} = $CMD_NAME{$cmd};
		$packet->{src} = $src_tnx;
		$packet->{dst} = $dst_tnx;
		$packet->{iseq} = $iseq;
		$packet->{oseq} = $oseq;
		$packet->{f} = $f;
		$packet->{r} = $r;
		$packet->{flags} = $flags;

		# find information elements, if they exist
		my $ie;
		if (length($buffer) > 12){
			$ie = substr($buffer, 8);
		}

		$packet->{ie} = $self->parse_ie($ie);
	}
	else{
		# invalid packet
	}

	return $packet;
}

sub parse_ie
{
	my $self = shift;
	my $buffer = shift;
	my $response = [];

	return $response if (!$buffer);

	my ($ie, $len);
	while ($buffer){
		($ie, $len, $buffer) = unpack('CCH*', $buffer);
		my $details = substr($buffer, 0, $len * 2);
		$details = pack('H*', $details);
		$buffer = substr($buffer, $len * 2);
		$buffer = $buffer ? pack('H*', $buffer) : undef;

		# if it's a valid element type
		if (defined $IE_NAME{$ie}){
			my $element = {
				type => $IE_NAME{$ie},
			};

			# IE specific details
			if ($ie eq $IE{'EID'}){
				$element->{id} = unpack('H12', $details);
			}
			# CALLEDCONTEXT
			elsif ($ie eq $IE{'CALLEDCONTEXT'}){
				$element->{context} = $details;
			}
			# CALLEDNUMBER
			elsif ($ie eq $IE{'CALLEDNUMBER'}){
				$element->{number} = $details;
			}
			# EIDDIRECT
			elsif ($ie eq $IE{'EIDDIRECT'}){
				$element->{id} = unpack('H12', $details);
			}
			# ANSWER
			elsif ($ie eq $IE{'ANSWER'}){
				# destination-specific data is 11 bytes past the beginning
				my $datalen = $len - 11;
				$datalen = 0 if ($datalen < 0);

				my ($eid, $protocol, $bits, $weight, $data) = unpack('H6CC2C2H'.$datalen, $details);
				$element->{eid} = $eid;
				if (defined $PROTOCOL_NAME{$protocol}){
					$element->{protocol} = $PROTOCOL_NAME{$protocol};
				}
				else{
					$element->{protocol} = $protocol;
				}
				$element->{weight} = $weight;
				$element->{destination} = $data;

				$element->{exists} = 1 if ($bits & (1 << 0));
				$element->{matchmore} = 1 if ($bits & (1 << 1));
				$element->{canmatch} = 1 if ($bits & (1 << 2));
				# following are reserved, but we'll include them just for fun
				$element->{ignorepat} = 1 if ($bits & (1 << 3));
				$element->{residential} = 1 if ($bits & (1 << 4));
				$element->{commercial} = 1 if ($bits & (1 << 5));
				$element->{mobile} = 1 if ($bits & (1 << 6));
				$element->{nounsolicited} = 1 if ($bits & (1 << 7));
				$element->{nocommercial} = 1 if ($bits & (1 << 8));
			}
			# TTL
			elsif ($ie eq $IE{'TTL'}){
				$element->{ttl} = hex(unpack('H*', $details));
			}
			# VERSION
			elsif ($ie eq $IE{'VERSION'}){
				$element->{version} = hex(unpack('H*', $details));
			}
			# EXPIRATION
			elsif ($ie eq $IE{'EXPIRATION'}){
				$element->{expiration} = hex(unpack('H*', $details));
			}
			# UNKNOWN
			elsif ($ie eq $IE{'UNKNOWN'}){
				$element->{unknown} = hex(unpack('H*', $details));
			}
			# CAUSE
			elsif ($ie eq $IE{'CAUSE'}){
				$element->{code} = unpack('C', $details);
				$element->{name} = $element->{code} ? $CAUSE_NAME{$element->{code}} : '';
				$element->{description} = substr($details, 1);
			}
			# REQEID
			elsif ($ie eq $IE{'REQEID'}){
				$element->{id} = unpack('H12', $details);
			}
			# ENCDATA
			elsif ($ie eq $IE{'ENCDATA'}){
				# per RFC, the remainder of the buffer is encdata
				# but... Asterisk seems to do it differently
				if ($len eq 0){
					$element->{encdata} = $buffer;
				}
				else{
					$element->{encdata} = $details;
				}
			}
			# SHAREDKEY
			elsif ($ie eq $IE{'SHAREDKEY'}){
				my $key = unpack('H*', $details);
				$element->{key} = $key;
			}
			# SIGNATURE
			elsif ($ie eq $IE{'SIGNATURE'}){
				my $sig = unpack('H*', $details);
				$element->{signature} = $sig;
			}
			# KEYCRC32
			elsif ($ie eq $IE{'KEYCRC32'}){
				$element->{keycrc32} = $details;
			}
			# HINT
			elsif ($ie eq $IE{'HINT'}){
				my ($ignore, $bits) = unpack('CC', $details);
				$element->{ttlexpired} = 1 if ($bits & (1 << 0));
				$element->{dontask} = 1 if ($bits & (1 << 1));
				$element->{unaffected} = 1 if ($bits & (1 << 2));
				$element->{hint} = substr($details, 2);
			}
			# DEPARTMENT
			elsif ($ie eq $IE{'DEPARTMENT'}){
				$element->{department} = $details;
			}
			# ORGANIZATION
			elsif ($ie eq $IE{'ORGANIZATION'}){
				$element->{organization} = $details;
			}
			# LOCALITY
			elsif ($ie eq $IE{'LOCALITY'}){
				$element->{locality} = $details;
			}
			# STATEPROV
			elsif ($ie eq $IE{'STATEPROV'}){
				$element->{stateprov} = $details;
			}
			# COUNTRY
			elsif ($ie eq $IE{'COUNTRY'}){
				$element->{country} = $details;
			}
			# EMAIL
			elsif ($ie eq $IE{'EMAIL'}){
				$element->{email} = $details;
			}
			# PHONE
			elsif ($ie eq $IE{'PHONE'}){
				$element->{phone} = $details;
			}
			# IPADDR
			elsif ($ie eq $IE{'IPADDR'}){
				$element->{ipaddr} = $details;
			}

			push @{$response}, $element;
		}
		else{
			# invalid (future protocol?) element type
			# ignore anything else in the stream
			$buffer = '';
		}
	}

	return $response;
}

sub encode
{
	my $self = shift;
	my $packet = shift;
	my $buffer = '';

	if (!defined $packet->{src}
		|| !defined $packet->{dst}
		|| !defined $packet->{iseq}
		|| !defined $packet->{oseq}
		|| !defined $packet->{r}
		|| !defined $packet->{f}
		|| !defined $packet->{flags}
		|| !defined $packet->{cmd}
		){
		return 1;
	}

	my $cmd = $CMD{$packet->{cmd}};
	if (!defined $cmd){
		return 2;
	}

	my $fld = ($packet->{f} ? 0x80 : 0);
	$fld |= ($packet->{r} ? 0x40 : 0);
	$fld |= ($cmd & 0x3f);

	$buffer = pack('SSCCCC', $packet->{src}, $packet->{dst}, $packet->{iseq}, $packet->{oseq}, $fld, $packet->{flags});

	if (defined $packet->{ie}){
		$buffer .= $self->encode_ie($packet->{ie});
	}

	return $buffer;
}

sub encode_ie
{
	my $self = shift;
	my $ie_array = shift;
	my $encoded = '';

	if (ref $ie_array ne 'ARRAY' || $#{$ie_array} eq -1){
		return '';
	}

	foreach my $ie (@{$ie_array}){
		if ($IE{$ie->{type}}){
			my $buffer = pack('C', $IE{$ie->{type}});

			# EID
			# expect a 12-digit hex string for $ie->{id}
			if ($ie->{type} eq 'EID'){
				# validation
				next if (!$ie->{id});

				# first the length
				$buffer .= pack('C', 6);
				# now the ID
				$buffer .= pack('H12', $ie->{id});
			}
			# CALLEDCONTEXT
			elsif ($ie->{type} eq 'CALLEDCONTEXT'){
				# validation
				next if (!$ie->{context});

				$buffer .= pack('C', length($ie->{context}));
				$buffer .= $ie->{context};
			}
			# CALLEDNUMBER
			elsif ($ie->{type} eq 'CALLEDNUMBER'){
				# validation
				next if (!$ie->{number});

				$buffer .= pack('C', length($ie->{number}));
				$buffer .= $ie->{number};
			}
			# EIDDIRECT
			# expect a 12-digit hex string for $ie->{id}
			elsif ($ie->{type} eq 'EIDDIRECT'){
				# validation
				next if (!$ie->{id});

				# first the length
				$buffer .= pack('C', 6);
				# now the ID
				$buffer .= pack('H12', $ie->{id});
			}
			# ANSWER
			elsif ($ie->{type} eq 'ANSWER'){
				# validation
				next if (!$ie->{eid});
				next if (!$ie->{protocol});
				next if (!$ie->{weight});
				next if (!Data::Types::is_int($ie->{weight}));
				next if (!$ie->{destination});

				my $protocol = 0;
				if ($PROTOCOL{$ie->{protocol}}){
					$protocol = $PROTOCOL{$ie->{protocol}};
				}
				else{
					next;
				}

				$buffer .= pack('C', length($ie->{destination}) + 11);
				$buffer .= pack('H12', $ie->{eid});
				$buffer .= pack('C', $protocol);

				my $bits = $ie->{nocommercial} ? 1 : 0;
				$buffer .= pack('C', $bits);

				$bits = 0;
				$bits |= $ie->{exists} ? (1 << 0) : 0;
				$bits |= $ie->{matchmore} ? (1 << 1) : 0;
				$bits |= $ie->{canmatch} ? (1 << 2) : 0;
				$bits |= $ie->{ignorepat} ? (1 << 3) : 0;
				$bits |= $ie->{residential} ? (1 << 4) : 0;
				$bits |= $ie->{commercial} ? (1 << 5) : 0;
				$bits |= $ie->{mobile} ? (1 << 6) : 0;
				$bits |= $ie->{nounsolicited} ? (1 << 7) : 0;
				$buffer .= pack('C', $bits);

				$buffer .= pack('n', $ie->{weight});
				$buffer .= $ie->{destination};
			}
			# TTL
			elsif ($ie->{type} eq 'TTL'){
				# validation
				next if (!$ie->{ttl});
				# TTL is numeric 16 bit int
				next if (!Data::Types::is_int($ie->{ttl}));
				next if ($ie->{ttl} > 0xff);
				next if ($ie->{ttl} < 0);

				# length is always 2
				$buffer .= pack('C', 2);
				$buffer .= pack('n', $ie->{ttl});
			}
			# VERSION
			elsif ($ie->{type} eq 'VERSION'){
				# validation
				next if (!$ie->{version});
				# we only support version 1
				next if ($ie->{version} != 1);

				$buffer .= pack('C', 2);
				$buffer .= pack('n', $ie->{version});
			}
			# EXPIRATION
			elsif ($ie->{type} eq 'EXPIRATION'){
				# validation
				next if (!$ie->{expiration});
				# expiration is numeric 16 bit int
				next if (!Data::Types::is_int($ie->{expiration}));
				next if ($ie->{expiration} > 0xffff);
				next if ($ie->{expiration} < 0);

				# length is always 2
				$buffer .= pack('C', 2);
				$buffer .= pack('n', $ie->{expiration});
			}
			# UNKNOWN
			elsif ($ie->{type} eq 'UNKNOWN'){
				# validation
				next if (!$ie->{unknown});
				# unknown command is numeric 16 bit int
				next if (!Data::Types::is_int($ie->{unknown}));
				next if ($ie->{unknown} > 0xffff);
				next if ($ie->{unknown} < 0);

				# length is always 2
				$buffer .= pack('C', 1);
				$buffer .= pack('C', $ie->{unknown});
			}
			# CAUSE
			elsif ($ie->{type} eq 'CAUSE'){
				# validation
				next if (!$ie->{code});
				next if (!Data::Types::is_int($ie->{code}));
				next if (!defined $CAUSE_NAME{$ie->{code}});
				next if (!$ie->{description});

				# TODO
				$buffer .= pack('C', length($ie->{description}) + 1);
				$buffer .= pack('C', $ie->{code});
				$buffer .= $ie->{description};
			}
			# REQEID
			elsif ($ie->{type} eq 'REQEID'){
				# validation
				next if (!$ie->{id});

				# first the length
				$buffer .= pack('C', 6);
				# now the ID
				$buffer .= pack('H12', $ie->{id});
			}
			# ENCDATA
			elsif ($ie->{type} eq 'ENCDATA'){
				# validation
				next if (!$ie->{encdata});

				# TODO
			}
			# SHAREDKEY
			elsif ($ie->{type} eq 'SHAREDKEY'){
				# validation
				next if (!$ie->{key});

				# max allowed is 0x80 (actually, it's the minimum too)
				my $len = length($ie->{key});
				next if ($len > 0x80);

				$buffer .= pack('C', $len);
				$buffer .= $ie->{key};
			}
			# SIGNATURE
			elsif ($ie->{type} eq 'SIGNATURE'){
				# validation
				next if (!$ie->{signature});

				# max allowed is 0x80 (actually, it's the minimum too)
				my $len = length($ie->{signature});
				next if ($len > 0x80);

				$buffer .= pack('C', $len);
				$buffer .= $ie->{signature};
			}
			# KEYCRC32
			elsif ($ie->{type} eq 'KEYCRC32'){
				# validation
				next if (!$ie->{keycrc32});

				$buffer .= pack('C', length($ie->{keycrc32}));
				$buffer .= $ie->{keycrc32};
			}
			# HINT
			# expect $ie->{hint} as a string
			# optionally expect $ie->{ttlexpired}
			# optionally expect $ie->{dontask}
			# optionally expect $ie->{unaffected}
			elsif ($ie->{type} eq 'HINT'){
				# validation
				next if (!$ie->{hint});

				my $bits = 0;
				$bits |= (1 << 0) if ($ie->{ttlexpired});
				$bits |= (1 << 1) if ($ie->{dontask});
				$bits |= (1 << 2) if ($ie->{unaffected});

				$buffer .= pack('C', length($ie->{hint}) + 2);
				$buffer .= pack('CC', 0, $bits);
				$buffer .= $ie->{hint};
			}
			# DEPARTMENT
			elsif ($ie->{type} eq 'DEPARTMENT'){
				# validation
				next if (!$ie->{department});

				$buffer .= pack('C', length($ie->{department}));
				$buffer .= $ie->{department};
			}
			# ORGANIZATION
			elsif ($ie->{type} eq 'ORGANIZATION'){
				# validation
				next if (!$ie->{organization});

				$buffer .= pack('C', length($ie->{organization}));
				$buffer .= $ie->{organization};
			}
			# LOCALITY
			elsif ($ie->{type} eq 'LOCALITY'){
				# validation
				next if (!$ie->{locality});

				$buffer .= pack('C', length($ie->{locality}));
				$buffer .= $ie->{locality};
			}
			# STATEPROV
			elsif ($ie->{type} eq 'STATEPROV'){
				# validation
				next if (!$ie->{stateprov});

				$buffer .= pack('C', length($ie->{stateprov}));
				$buffer .= $ie->{stateprov};
			}
			# COUNTRY
			elsif ($ie->{type} eq 'COUNTRY'){
				# validation
				next if (!$ie->{country});

				$buffer .= pack('C', length($ie->{country}));
				$buffer .= $ie->{country};
			}
			# EMAIL
			elsif ($ie->{type} eq 'EMAIL'){
				# validation
				next if (!$ie->{phone});

				$buffer .= pack('C', length($ie->{email}));
				$buffer .= $ie->{email};
			}
			# PHONE
			elsif ($ie->{type} eq 'PHONE'){
				# validation
				next if (!$ie->{phone});

				$buffer .= pack('C', length($ie->{phone}));
				$buffer .= $ie->{phone};
			}
			# IPADDR
			elsif ($ie->{type} eq 'IPADDR'){
				# validation
				next if (!$ie->{ipaddr});

				$buffer .= pack('C', length($ie->{ipaddr}));
				$buffer .= $ie->{ipaddr};
			}

			$encoded .= $buffer;
		}
	}

	return $encoded;
}

1;

__END__
