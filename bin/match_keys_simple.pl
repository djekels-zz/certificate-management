#!/usr/bin/perl
#
# Take two keys, and attempt to match them up
#
# author: pblair@tucows.com

my @list = sort( @ARGV );
my (@name, @modulus);

for ( @list ){
	my $sum;
	if ( /\.crt(?:\.\d{4})?$/i ){
		$sum = `openssl x509 -noout -modulus -in $_ | openssl md5`;
		push( @name, $_ );
		push( @modulus, $sum );
	}
	elsif( /\.key(?:\.\d{4})?$/i ){
		$sum = `openssl rsa -noout -modulus -in $_ | openssl md5`;
		push( @name, $_ );
		push( @modulus, $sum );
	}
	elsif( /\.csr(?:\.\d{4})?$/i ){
		$sum = `openssl req -noout -modulus -in $_ | openssl md5`;
		push( @name, $_ );
		push( @modulus, $sum );
	}
}

while (@name){
	my ($name,$modulus) = ( shift(@name), shift(@modulus) );
	chomp $name;
	chomp $modulus;
	print "$name $modulus\n";
}
exit 0;
