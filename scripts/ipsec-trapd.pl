#!/usr/bin/perl
#
# Copyright (c) 2015, Brocade Communications Systems, Inc.
# Copyright (c) 2018, AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#

use warnings;
use strict;
use subs qw(init snmp_init cleanup sa2trap parse loop sendTrap uptime
	    name usage fatal gripe goodbye mkoids);

use constant EX_OK => 0;
use constant EX_USAGE => 64;
use constant EX_SOFTWARE => 70;
use constant EX_OSERR => 71;

use lib "/opt/vyatta/share/perl5";

use File::Basename;
use File::Slurp;
use IO::Interface::Simple;
use IO::Socket;
use Getopt::Long;
use POSIX qw(uname SIGKILL);
use Net::SNMP qw(:ALL);
use Sys::Syslog qw(:standard :macros);
use Config::IniFiles;

use constant ticksHz => 100;

use constant {
    stateDown => 1,
    stateUp => 2,
    directionInbound => 1,
    directionOutbound => 2,
    modeTunnel => 1,
    modeTransport => 2,
    encapAH => 1,
    encapESP => 2,
};

my $prog = basename($0);

my $default_port = getservbyname('snmp-trap', 'udp');

my $sock = IO::Socket::INET->new(Proto => 'udp');

my %hashes = ();

my $detached = undef;

my $config_file = '/etc/snmp/trapd.ini';
my @sess;
my $descr;

my $pipe;
my $testfile;
my $background;
my $pidfile;

openlog($prog, "pid", LOG_DAEMON);

(GetOptions(
	"testfile=s" => \$testfile,
	"background" => \$background,
	"pidfile=s" => \$pidfile
  ) && scalar @ARGV == 0)
    || usage();

mkoids([
    iso => [qw(1)],
    identified_organization => [qw(iso 3)],
    dod => [qw(identified_organization 6)],
    internet => [qw(dod 1)],
    private => [qw(internet 4)],

    mgmt => [qw(internet 2)],
    mib_2 => [qw(mgmt 1)],
    system => [qw(mib_2 1)],
    sysDescr => [qw(system 1)],
    sysObjectID => [qw(system 2)],
    sysUpTime => [qw(system 3)],
    sysName => [qw(system 5)],
    sysLocation => [qw(system 6)],
    snmpV2 => [qw(internet 6)],
    snmpModules => [qw(snmpV2 3)],
    snmpMIB => [qw(snmpModules 1)],
    snmpMIBObjects => [qw(snmpMIB 1)],
    snmpTrap => [qw(snmpMIBObjects 4)],
    snmpTrapOID => [qw(snmpTrap 1)],

    enterprises => [qw(private 1)],
    bcsi => [qw(enterprises 1588)],
    bcsiReg => [qw(bcsi 3)],
    bcsiModules => [qw(bcsiReg 1)],

    brocadeIPSecMIB => [qw(bcsiModules 5)],
    brocadeIPSecMIBNotifs => [qw(brocadeIPSecMIB 0)],
    brocadeIPSecMIBObjects => [qw(brocadeIPSecMIB 1)],
    brocadeIPSecMIBConform => [qw(brocadeIPSecMIB 2)],

    bipsNotifObjects => [qw(brocadeIPSecMIBObjects 1)],
    bipsSaSpi => [qw(bipsNotifObjects 1)],
    bipsSaLocalAddr => [qw(bipsNotifObjects 2)],
    bipsSaRemoteAddr => [qw(bipsNotifObjects 3)],
    bipsSaDirection => [qw(bipsNotifObjects 4)],
    bipsSaMode => [qw(bipsNotifObjects 5)],
    bipsSaEncap => [qw(bipsNotifObjects 6)],
    bipsSaState => [qw(bipsNotifObjects 7)],

    bipsSaStateChange => [qw(brocadeIPSecMIBNotifs 1)],
    ]);

goodbye "Insufficient SNMP state" unless init();

if (defined $testfile) {
    open($pipe, '<', $testfile) || fatal "Can't open testfile: %s", $!;
}

if ($background) {
    my $pid = fork();

    if (! defined $pid) {
	gripe "Couldn't fork child: %s", $!;
	cleanup();
	exit(EX_OSERR);
    } elsif ($pid > 0) {
	if (open(my $file, '>', $pidfile)) {
	    printf $file "%d\n", $pid;
	    close($file);
	} else {
	   gripe "Unable to open pidfile for writing: %s", $!;
	}
	$pidfile = undef;	# so it's not clobbered on parent exit
	cleanup();
	exit(EX_OK);
    } else {
	$detached = 1;
	close(STDIN);
	close(STDOUT);
	close(STDERR);
	if (! defined $testfile) {
	    open($pipe, '-|', 'ip -o xfrm monitor') || fatal "Can't start subcommand: %s", $!;
	}
    }
} else {
    if (! defined $testfile) {
	open($pipe, '-|', 'ip -o xfrm monitor') || fatal "Can't start subcommand: %s", $!;
    }
}

loop($pipe);

cleanup();

exit(EX_OK);

sub init
{
    return 0 unless (-e $config_file);

    return snmp_init();
}

sub snmp_init
{
    my $cfg = Config::IniFiles->new( -file => $config_file );
    if (! defined $cfg) {
	gripe "Error opening $config_file";
	return 0;
    };

    if (! $cfg->SectionExists('general') ) {
	gripe "general section missing";
	return 0;
    }

    $descr = $cfg->val( 'general', 'description' );
    if (! defined $descr) {
	gripe "Need description set";
	return 0;
    }

    my @default_communities = split / /, $cfg->val( 'general', 'community', '');
    my $source = $cfg->val( 'general', 'trap-source', undef);
    my @args = defined $source ? (-localaddr => $source) : ();

    # need to check for snmp v3 being configured, which is unsupported

    foreach my $target ($cfg->GroupMembers('trap-target')) {
	my $address =  $cfg->val( $target, "address" );
	if (! defined $address) {
	    gripe "No address for %s", $target;
	    next;
	}

	my $port = $cfg->val( $target, "port", $default_port );
	my $community = $cfg->val( $target, "community");
	if (! defined $community) {
	    # If there is only one global community, then that's an
	    # unambiguous default. If there are multiple ones, then
	    # one needs to be explicitly bound to the trap-target(s).
	    if (scalar @default_communities != 1) {
		gripe "Need community set for trap-target %s", $address;
		next;
	    }
	    $community = $default_communities[0];
	}

	my ($s, $error) = Net::SNMP->session(
	    -hostname => $address,
	    -port => $port,
	    -community => $community,
	    -version => 'snmp2c',
	    @args,
	);

	if (! defined $s) {
	    gripe "Can't create session for target %s", $address;
	    next;
	}

	# no other verification, just push onto list...
	push(@sess, $s);
    }

    return scalar @sess;
}

sub cleanup
{
    for (my $i = 0; $i < scalar @sess; ++$i) {
	$sess[$i]->close();
    }

    close($pipe) if (defined $pipe);

    if (defined $pidfile) {
	if (! unlink($pidfile)) {
	    gripe "Can't remove pidfile on exit: %s", $!;
	}
    }

    closelog();
    return;
}

sub sa2trap
{
    my $sa = shift;

    for (my $i = 0; $i < scalar @sess; ++$i) {
	sendTrap(
	    $sess[$i],
	    &bipsSaStateChange,
	    $sa->{spi},
	    $sa->{src},
	    $sa->{dst},
	    $sa->{outbound} ? directionOutbound : directionInbound,
	    ($sa->{mode} eq 'tunnel' ? modeTunnel : modeTransport),
	    ($sa->{proto} eq 'ah' ? encapAH : encapESP),
	    ($sa->{deleted} ? stateDown : stateUp),
	    $descr,
	    name(), 
	);
    }
    return;
}

sub parse
{
    my $buffer = shift;

    # IKE key events, ignore
    return if (substr($buffer, 0, 8) eq "Expired " || substr($buffer, 0, 8) eq "Updated ");

    $buffer =~ /src ([^ ]+) dst ([^ ]+) proto (ah|esp) spi (0x[0-9a-f]{8}) .* mode (tunnel|transport) /;
    return unless (defined $1);

    my $sa = {};

    $sa->{src} = $1;
    $sa->{dst} = $2;
    $sa->{proto} = $3;
    $sa->{spi} = hex($4);
    $sa->{mode} = $5;
    $sa->{deleted} = (substr($buffer, 0, 8) eq "Deleted ") ? 1 : 0;
    my $ifname = $sock->addr_to_interface($1);
    $sa->{outbound} = defined $ifname ? 1 : 0;

    return $sa;
}

sub loop
{
    my $handle = shift;
    my $sa = undef;

    while (my $line = <$handle>) {
	chomp $line;

	$line =~ s/ ?\\$//;
	$line =~ s/ ?\\\t/ /g;
	if ($sa = parse($line)) {
	    sa2trap($sa);
	}
    }

    return;
}

sub sendTrap
{
    my ($sess, $oid, $spi, $local, $remote, $direction, $mode, $encap, $state, $descr, $name) = @_;

    my $result = $sess->snmpv2_trap(
	-varbindlist => [
	    # preamble
	    &sysUpTime . '.0', TIMETICKS, uptime(),
	    &snmpTrapOID . '.0', OBJECT_IDENTIFIER, $oid,

	    # trap-specific stuff
	    &bipsSaSpi . '.0', UNSIGNED32, $spi,
	    &bipsSaLocalAddr . '.0', IPADDRESS, $local,
	    &bipsSaRemoteAddr . '.0', IPADDRESS, $remote,
	    &bipsSaDirection . '.0', INTEGER, $direction,
	    &bipsSaMode . '.0', INTEGER, $mode,
	    &bipsSaEncap . '.0', INTEGER, $encap,
	    &bipsSaState . '.0', INTEGER, $state,

	    # postamble
	    &sysDescr . '.0', OCTET_STRING, $descr,
	    &sysName . '.0', OCTET_STRING, $name,
	],
    );
 
    if (!defined $result) {
	gripe "Couldn't send: %s", $sess->error();
    }

    return defined $result;
}

sub uptime
{
    # this is highly Linux-dependent...
    my $line = read_file('/proc/uptime');
    my ($uptime, $idle) = split(/ /, $line);

    return $uptime * ticksHz;
}

sub name
{
    return (uname())[1];
}

sub usage
{
    print STDERR "Usage: $prog [ --background ] [ --pidfile file ] [ --testfile file ]\n";
    exit(EX_USAGE);
}

sub fatal
{
    my ($fmt, @args) = @_;

    if ($detached) {
	syslog(LOG_ERR, $fmt, @args);
	exit(EX_SOFTWARE);
    } else {
	# sprintf does strange things if the first argument is an array
	die sprintf($fmt, @args) . "\n";
    }
}

sub gripe
{
    my ($fmt, @args) = @_;

    if ($detached) {
	syslog(LOG_WARNING, $fmt, @args);
    } else {
	# sprintf does strange things if the first argument is an array
	warn sprintf($fmt, @args) . "\n";
    }
    return;
}

sub goodbye
{
    my ($fmt, @args) = @_;

    if ($detached) {
        syslog(LOG_WARNING, $fmt, @args);
    } else {
        printf $fmt . "\n", @args;
    }
    cleanup();
    exit(EX_OK);
}

sub mkoids
{
    my $ref = shift;

    fatal "Not a list of tuples" unless (scalar @{$ref} % 2 == 0);

    for (my $i = 0; $i < scalar @{$ref}; $i += 2) {
	my $name = $ref->[$i];

	fatal "Not a valid OID name: %s", $name unless ($name =~ /^[a-z][a-zA-Z0-9_]*$/);

	my $vals = $ref->[$i + 1];
	my $oid;
	if (scalar @{$vals} == 1) {
	    $oid = $vals->[0];
	    fatal "OID not integer!" unless ($oid =~ /^\d+$/);
	} elsif (scalar @{$vals} == 2) {
	    my $root = $vals->[0];
	    my $suffix = $vals->[1];
	    fatal "Prefix $root not defined!" unless (exists $hashes{$root});
	    fatal "Suffix for $name not integer!" unless ($suffix =~ /^\d+$/);
	    $oid = $hashes{$root} . '.' . $suffix;
	} else {
	    # do we want to allow { iso 5 6 7 } ?
	    fatal "Too many values for OID $name";
	}

	eval "sub $name { return \"$oid\"; }";
	eval "use subs qw($name);";
	$hashes{$name} = $oid;
    }

    return;
}

