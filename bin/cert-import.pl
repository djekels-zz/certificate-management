#!/usr/bin/perl
use strict;
use Data::Dumper;
use File::Basename;

my $DB = '/home/pblair/managed-certs/db';

sub cn {
	my $file = shift;
	my $res = `openssl x509 -noout -subject < $file`;
	chomp $res;

	my $cn = $1 if ( $res =~ /CN=(\S.*)/ );

	if ($cn =~ /\/[A-Z]+=/ ){
		my @a = split( /\//, $cn );
		$cn = $a[0];
	}

	$cn =~ s/\*/wildcard/g;
	$cn =~ s/\s+/_/g;

	return $cn;
}

sub find_matching_modulus {
	my $modulus = shift;

	my %certs = map { split /\s+/ } `find $DB -type f|xargs match_keys_simple.pl`;

	print "Matching modulus[$modulus] : " . Dumper( \%certs ) . "\n";

	my @match = grep { $modulus eq $certs{$_}  } keys %certs ;

	print "Matched: " . join( " ", @match ) . "\n";
	return \@match;
}

my $cert = shift or die;
my $verb = shift;
my $name = shift;

$verb = lc $verb;

`mkdir -p $DB/$name`
	unless -d "$DB/$name";

die "$DB/$name doesn't exist"
	unless -d "$DB/$name";

die "$cert isn't a file"
	unless -f $cert;

if ($cert =~ /\.crt$/){
	my $CN = cn( $cert );

	die "Could not determine CN from $cert"
		unless $CN;

	unless ($name){
		$name = $CN;
	}

	my $expires = `echo $cert | ssl-cert-check.pl -f - -e`;
	$expires = $1 if ( $expires =~ /:\s*(\d+)/ );

	print "$DB/$name/$CN.crt[$name] expires: $expires\n";

	if (defined $expires){
		`mkdir -p $DB/$name/$expires`;
		`cp -a $cert $DB/$name/$expires/`;
	}

	exit 0;
}

if ($cert =~ /\.(csr|key)$/){
	my $extension = $1;
	my $csr = $cert;
	print "Importing $cert as a CSR\n";
	my $modulus = `match_keys_simple.pl $cert|tail -1|awk '{print \$NF}'`;
	chomp($modulus);
	my $csr_modulus = $modulus;

	print "Modulus : $modulus\n";

	my $matched = find_matching_modulus $modulus;
		
	die "No certs with matching modulus of $csr_modulus"
		unless grep { /\.crt$/ } @$matched;

	unless ($name){
		my @matched_crt = grep { /\.crt$/ } @$matched ;
		$name = cn( $matched_crt[0] );
	}

	`cp -a $csr $DB/$name/$name.$csr_modulus.$extension`
		unless -e "$DB/$name/$name.$csr_modulus.$extension";

	for my $matching_cert ( grep { /\.crt$/ } @$matched ){
		print "Matching cert: $matching_cert\n";
		my $dn = dirname($matching_cert);
		`ln -sf $DB/$name/$name.$csr_modulus.$extension $dn/$name.$extension`
			unless -e "$dn/$name.$extension";
	}
	exit 0;
}

die "$cert: Unknown file type";


