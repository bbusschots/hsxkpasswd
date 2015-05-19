#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Crypt::HSXKPasswd' ) || print "Bail out!\n";
}

diag( "Testing Crypt::HSXKPasswd $Crypt::HSXKPasswd::VERSION, Perl $], $^X" );
