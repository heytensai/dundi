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

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(
	new
	parse
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

	my ($src_tnx, $dst_tnx, $iseq, $oseq, $fld, $flags, $ie) = unpack('nnCCCCH*', $buffer);
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

		# convert IE back
		$ie = $ie ? pack('H*', $ie) : '';

		$packet->{ie} = $self->parse_ie($cmd, $ie, $ie);
	}
	else{
		# invalid packet
	}

	return $packet;
}

sub parse_ie
{
	my $self = shift;
	my $cmd = shift;
	my $buffer = shift;
	my $response = [];

	return $response if (!$buffer);

	my ($ie, $len);
	my $count = 10;
	while ($buffer && $count--){
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
				$element->{id} = unpack('H6', $details);
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
				# TODO
				$element->{encdata} = '';
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
				# TODO
				$element->{keycrc32} = '';
			}
			# HINT
			elsif ($ie eq $IE{'HINT'}){
				# TODO
				$element->{hint} = '';
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

1;

__END__
