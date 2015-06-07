package Crypt::HSXKPasswd::RNG;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Readonly; # for truly constant constants
use Crypt::HSXKPasswd::Helper; # exports utility functions like _error & _warn

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

# Copyright (c) 2015, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# HSXKPasswd.pm)

#
# --- Constants ---------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.2');

# utility variables
Readonly my $_CLASS => __PACKAGE__;

#
# --- Constructor -------------------------------------------------------------
#

#####-SUB-#####################################################################
# Type       : CONSTRUCTOR (CLASS)
# Purpose    : A place-holder for the constructor - just throws an error
# Returns    : VOID
# Arguments  : NONE
# Throws     : ALWAYS throws an error to say this class must be extended.
# Notes      : 
# See Also   :
## no critic (Subroutines::RequireFinalReturn);
sub new{
    _error("$_CLASS must be extended to be used");
}
## use critic

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A place-holder for the function to get n random numbers.
# Returns    : NOTHING - but in subclasses should return an array of random
#              numbers between 0 and 1.
# Arguments  : 1) the number of random numbers needed to generate a single
#                 password.
# Throws     : ALWAYS throws an error to say this class must be extended, and
#              this function must be overridden.
# Notes      :
# See Also   :
## no critic (Subroutines::RequireFinalReturn);
sub random_numbers{
    _error("$_CLASS must be extended to be used, and the function random_numbers() must be overridden");
}
## use critic

1; # because Perl is just a little bit odd :)