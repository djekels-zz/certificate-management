#!/usr/bin/perl
use strict;

my $DB = '/home/pblair/managed-certs/db';

my $name = shift or die;

`mkdir -p $DB/$name`;

die "$DB/$name doesn't exist"
	unless -d "$DB/$name";



