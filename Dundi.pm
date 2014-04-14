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

	my ($src_tnx, $dst_tnx, $iseq, $oseq, $fld, $flags, $ie) = unpack('nnCCCCC*', $buffer);
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

		$packet->{ie} = $self->parse_ie($cmd, $ie);
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

	my ($ie, $len, $data) = unpack('CCC*', $buffer);

	# TODO add a loop

	# if it's a valid element type
	if (defined $IE{$ie}){
		my $element = {
			type => $IE{$ie},
		};

		# IE specific details
		if ($ie eq $IE{'EID'}){
			if ($len ne 0x06){
				print " invalid\n";
			}
			else{
				my $id = unpack('H*', $data);
				$element->{id} = $id;
			}
		}
		elsif ($ie eq $IE{'CALLEDCONTEXT'}){
			my $context = unpack('H*', $data);
			$element->{context} = $context;
		}
		elsif ($ie eq $IE{'CALLEDNUMBER'}){
			my $number = unpack('H*', $data);
			$element->{number} = $number;
		}
		elsif ($ie eq $IE{'EIDDIRECT'}){
		}
		elsif ($ie eq $IE{'ANSWER'}){
		}
		elsif ($ie eq $IE{'TTL'}){
		}
		elsif ($ie eq $IE{'VERSION'}){
		}
		elsif ($ie eq $IE{'EXPIRATION'}){
		}
		elsif ($ie eq $IE{'UNKNOWN'}){
		}
		elsif ($ie eq $IE{'CAUSE'}){
		}
		elsif ($ie eq $IE{'REQEID'}){
		}
		elsif ($ie eq $IE{'ENCDATA'}){
		}
		elsif ($ie eq $IE{'SHAREDKEY'}){
		}
		elsif ($ie eq $IE{'SIGNATURE'}){
		}
		elsif ($ie eq $IE{'KEYCRC32'}){
		}
		elsif ($ie eq $IE{'HINT'}){
		}
		elsif ($ie eq $IE{'DEPARTMENT'}){
		}
		elsif ($ie eq $IE{'ORGANIZATION'}){
		}
		elsif ($ie eq $IE{'LOCALITY'}){
		}
		elsif ($ie eq $IE{'STATEPROV'}){
		}
		elsif ($ie eq $IE{'COUNTRY'}){
		}
		elsif ($ie eq $IE{'EMAIL'}){
		}
		elsif ($ie eq $IE{'PHONE'}){
		}
		elsif ($ie eq $IE{'IPADDR'}){
		}

		push @{$response}, $element;
	}

	return $response;
}

1;

__END__
