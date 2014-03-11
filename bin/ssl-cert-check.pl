#!/usr/bin/perl
#
# Little application to retrieve the certficate from a remote
# system, and check the expiry date of that cert against the
# time of the local system.
#
# Author:		pblair(at)tucows(dot)com
# Last Modified:	Tue Sep  1 10:19:20 EDT 2009
#
use strict;
use Getopt::Std;
use IPC::Open2;
use IPC::Open3;
use Time::Local;

###
## Global Variables
###
my $verbose = 0;

###
### Set the help applications
###

my $DATE = `which date`;	chomp( $DATE );
my $SSL  = `which openssl`;	chomp( $SSL );

###
### Functions
###

# This routine currently only works for HTTP retrieval.
sub getcert( $$ ){
	my ($host,$port) = @_;

	my $command = "$SSL s_client -connect ${host}:${port} 2>&1";
	print "Calling [$command]\n" if $verbose;
	my $pid = open2(\*RDR, \*WTR, $command );

	print WTR "get /\r\n";

	my $ssltxt = do{ local $/; <RDR>; };

	my $cert = $1 if( $ssltxt =~ /(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)/gsm);

	return $cert
}

sub certExpiry( $ ){
	my ($crt) = @_;

	print "Calculating cert expiry\n" if $verbose;
	my $pid = open2(\*RDR, \*WTR, "${SSL} x509 -enddate");

	print WTR "$crt\n";
	my $txt = do { local $/; <RDR>; };

	my $expires = $1 if ( $txt =~ /notAfter=(.*)/ );

	# Example: notAfter=Apr 18 13:55:24 2010 GMT

	if( $expires =~ /(\S+?)\s+(\d+?)\s+\S+\s+(\d+?)\s+/ ){
		my ($m,$d,$y) = ($1,$2,$3);

		# Convert month to numeric
		$m = 0 if( $m =~ /Jan/i );
		$m = 1 if( $m =~ /Feb/i );
		$m = 2 if( $m =~ /Mar/i );
		$m = 3 if( $m =~ /Apr/i );
		$m = 4 if( $m =~ /May/i );
		$m = 5 if( $m =~ /Jun/i );
		$m = 6 if( $m =~ /Jul/i );
		$m = 7 if( $m =~ /Aug/i );
		$m = 8 if( $m =~ /Sep/i );
		$m = 9 if( $m =~ /Oct/i );
		$m = 10 if( $m =~ /Nov/i );
		$m = 11 if( $m =~ /Dec/i );	
		
		my $time = timegm( 0, 0, 0, $d, $m, $y );
		return( $time,$expires );
	}
	return( 0,0 );
}

###
### MAIN
###

my %options;
my ($host,$port);
my @work;

getopts("h:f:C:cedrv",\%options);

$verbose = 1 if defined $options{v};

die("You must supply a host:port with -h\n") unless( defined $options{h} || defined $options{f} || defined $options{C} );

if( defined $options{h} ){
	if( $options{h} =~ /(\S+?):(\d+)/ ){
		($host,$port) = ($1,$2);
		push( @work, [ $host, $port ]);
	}
	elsif( $options{h} =~ /^(\S+)$/ ){
		$host = $1;
		push( @work, [ $host, 443 ] );
	}
}
elsif( defined $options{f} ){
	open FD, "<$options{f}";
	while( <FD> ){
		chomp;
		s/\s//g;
		print "Reading [$_]\n" if $verbose;
		next if /^#/;
		next if /^\s+/;
		if( /(\S+?):(\d+)/ ){
			($host,$port) = ($1,$2);
			push( @work, [ $host, $port ] );
		}
		elsif( /\.crt/i ){
			# We want to look up a cert file!
			push( @work, [ $_, undef ] );
		}
		elsif( /^(\S+)$/ ){
			$host = $1;
			push( @work, [ $host, 443 ] );
		}
	}
}
elsif( defined $options{C} ){
	push( @work, [ $options{C}, undef ] );
}

my (@resDelta, @resName, @resExp );

for( @work ){
	my ($host,$port) = @$_;
	my $cert = '';

	if( $host =~ /\.crt/i ){
		# Chances are that we're looking
		# for a file
		open FD, "<$host";
		my $ssltxt = do { local $/; <FD>; };
		print "Extracting cert from [$host]\n" if $verbose;	
		$cert = $1 if( $ssltxt =~ /(-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----)/gsm);
	}
	else {
		print "Getting cert from [$host:$port]\n" if $verbose;
		$cert = getcert( $host, $port );
	}
	print $cert . "\n" if $options{c};

	next if( $cert eq '' );

	# Get the expiration date
	my ($expiry,$txtexpiry) = certExpiry( $cert );

	print "Cert expires on: $expiry\n" if $options{e};

	# Get how many days until expiration
	my $now = time();
	my $delta = $expiry - $now;
	$delta /= ( 60 * 60 * 24 );
	$delta = sprintf "%d", $delta;

	printf "Cert expires in %d days\n", $delta if $options{d};
	my $name = "$host:$port";
	push( @resName, $name );
	push( @resDelta, $delta );
	push( @resExp, $txtexpiry );

}

if( $options{r} ){

	format STDOUT =
Name                                           | Expires                  |   Days Left
-----------------------------------------------+--------------------------+---------------
@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< | @<<<<<<<<<<<<<<<<<<<<<<< | @>>>>>>>>>> ~~
shift( @resName ),                            shift( @resExp ),          shift( @resDelta )
.
	write;
}
