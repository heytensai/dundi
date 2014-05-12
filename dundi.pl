#!/usr/bin/perl
#
# sample Dundi.pm application
#
# Copyright (c) 2014 Corey Edwards <tensai@zmonkey.org>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;
use threads;
use feature "switch";

use IO::Socket::INET;
use Data::Dumper;
use Term::ReadLine;
use Config::IniFiles;
use Dundi;

# CONFIG VARS
my $port = 4520;
# END CONFIG VARS

my $sock = IO::Socket::INET->new(LocalPort => $port, Proto => 'udp', ReuseAddr => 1);

my $dundi = Dundi->new();

my $listen_thread = threads->create(\&listener);

sleep(1);
command_loop();

sub command_loop
{
	print "dundi> ";
	while (my $cmd = <STDIN>){
		chomp $cmd;
		if ($cmd eq 'quit'){
			print "cleaning up\n";
			$listen_thread->kill('KILL')->detach;
			exit;
		}
		elsif ($cmd =~ /^ping ([\d\.]+)/){
			print "ping $1\n";
			#send_ping();
		}
		print "dundi> ";
	}
}

sub listener
{
	local $SIG{KILL} = sub { threads->exit };
	print "listening on port $port\n";
	while (1){
		my $buffer;
		$sock->recv($buffer, 1024);
		my $peer_address = $sock->peerhost();
		my $peer_port = $sock->peerport();

		print "datagram received from $peer_address, $peer_port";
		print " len " . length($buffer);
		print "\n";

		my $hex = unpack('H*', $buffer);
		print "hex=$hex\n";

		my $packet = $dundi->parse($buffer);
		print "cmd=$packet->{cmd}\n";
		#print Dumper($packet);

		if ($packet->{cmd} eq 'NULL'){
			send_ack($packet, 1);
		}
		elsif ($packet->{cmd} eq 'DPDISCOVER'){
			print Dumper($packet);
			my $tnx = generate_transaction();
			send_ack($packet, 0, $tnx);
			send_dpresponse($packet, $tnx);
		}

		print "----------------------\n";
	}
}

sub generate_transaction
{
	my $tnx = int(rand(0xffff));
	return $tnx;
}

sub send_dpresponse
{
	my $req = shift;
	my $tnx = shift;

	my $response = {
		cmd => 'DPRESPONSE',
		dst => $req->{src},
		src => generate_transaction(),
		f => 1,
		r => 1,
		flags => 0,
		oseq => 0,
		iseq => 1,
	};
	my $pkt = $dundi->encode($response);
	$sock->send($pkt);
}

sub send_ack
{
	my $req = shift;
	my $f = shift || 0;
	my $tnx = shift || generate_transaction();
	print "sending ACK\n";
	my $response = {
		cmd => 'ACK',
		dst => $req->{src},
		src => $tnx,
		f => $f,
		r => 1,
		flags => 0,
		oseq => 0,
		iseq => $req->{oseq} + 1,
	};
	my $pkt = $dundi->encode($response);
	$sock->send($pkt);
}

sub send_ping
{
	print "sending ping\n";
	my $req = {
		cmd => 'NULL',
		dst => 0,
		src => generate_transaction(),
		f => 0,
		r => 1,
		flags => 0,
		oseq => 0,
		iseq => 0,
	};
	my $pkt = $dundi->encode($req);
	$sock->send($pkt);
}

