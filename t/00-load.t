#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 3;

BEGIN {
    use_ok( 'Crypt::HSXKPasswd' ) || print "Bail out!\n";
    use_ok( 'Crypt::HSXKPasswd::Dictionary::EN' ) || print "Bail out!\n";
    use_ok( 'Crypt::HSXKPasswd::RNG::Basic' ) || print "Bail out!\n";
}

diag( "Testing Crypt::HSXKPasswd $Crypt::HSXKPasswd::VERSION, Perl $], $^X" );
