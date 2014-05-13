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
use threads::shared;
use feature "switch";

use IO::Socket::INET;
use Data::Dumper;
use Term::ReadLine;
use Config::IniFiles;
use Dundi;

# CONFIG VARS
my $default_port = 4520;
my $cfg_file = shift || 'dundi.ini';
# END CONFIG VARS

my $cfg = Config::IniFiles->new(-file => $cfg_file);
my $port = $cfg->val('general', 'port') || $default_port;
my $eid = $cfg->val('general', 'eid');

my $sock = IO::Socket::INET->new(LocalPort => $port, Proto => 'udp', ReuseAddr => 1);

my $dundi = Dundi->new();

my %stats :shared = ();
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
		elsif ($cmd =~ /^stats$/){
			{
				lock(%stats);
				print Data::Dumper::Dumper(\%stats);
			}
		}
		elsif ($cmd =~ /^context show (.*)$/){
			if ($cfg->SectionExists($1)){
				my @keys = $cfg->Parameters($1);
				map { print "$_=" . $cfg->val($1, $_) . "\n"; } @keys;
			}
			else{
				print "no context\n";
			}
		}
		elsif ($cmd =~ /^reload$/){
			$cfg = Config::IniFiles->new(-file => $cfg_file);
			print "config reloaded\n";
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
		{
			lock(%stats);
			$stats{total} += 1;
		}
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
			{
				lock(%stats);
				$stats{pings} += 1;
			}
		}
		elsif ($packet->{cmd} eq 'DPDISCOVER'){
			{
				lock(%stats);
				$stats{lookups} += 1;
			}
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

	my $context;
	my $number;
	foreach my $ie (@{$req->{ie}}){
		if ($ie->{type} eq 'CALLEDNUMBER'){
			$number = $ie->{number};
		}
		elsif ($ie->{type} eq 'CALLEDCONTEXT'){
			$context = $ie->{context};
		}
	}
	print "context=$context\n";
	print "number=$number\n";

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

	if ($context && $number){
		 if ($cfg->exists($context, $number)){
			 my $route = $cfg->val($context, $number);
			 # TODO assemble IEs for the response
			 print "found a route to $route\n";
		 }
	}

	my $pkt = $dundi->encode($response);
	{
		lock(%stats);
		$stats{responses} += 1;
	}
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
	{
		lock(%stats);
		$stats{responses} += 1;
	}
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
	{
		lock(%stats);
		$stats{responses} += 1;
	}
	$sock->send($pkt);
}

