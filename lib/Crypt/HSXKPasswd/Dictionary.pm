package Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Scalar::Util qw(blessed); # for checking if a reference is blessed
use Crypt::HSXKPasswd; # for the error function

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
# --- 'Constants' -------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.1_01');

# utility variables
my $_CLASS = __PACKAGE__;
my $_MAIN_CLASS = 'Crypt::HSXKPasswd';

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
    $_MAIN_CLASS->_error("$_CLASS must be extended to be used");
}
## use critic

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : A place-holder for the function to clone self.
# Returns    : NOTHING - but in subclasses should return a clone of self
# Arguments  : NONE
# Throws     : ALWAYS throws an error to say this class must be extended, and
#              this function must be overridden.
# Notes      :
# See Also   :
## no critic (Subroutines::RequireFinalReturn);
sub clone{
    $_MAIN_CLASS->_error("$_CLASS must be extended to be used, and the function clone() must be overridden");
}
## use critic

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A place-holder for the function to get the list of words.
# Returns    : NOTHING - but in subclasses should return an array ref.
# Arguments  : NONE
# Throws     : ALWAYS throws an error to say this class must be extended, and
#              this function must be overridden.
# Notes      :
# See Also   :
## no critic (Subroutines::RequireFinalReturn);
sub word_list{
    $_MAIN_CLASS->_error("$_CLASS must be extended to be used, and the function word_list() must be overridden");
}
## use critic

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A function to return the source of the words as a string
# Returns    : A scalar string
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub source{
    my $self = shift;
    
    # validate args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    # return the instances class
    return blessed($self);
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A function to print out the words in the dictionary
# Returns    : Always returns 1 (to keep PerlCritic happy)
# Arguments  : NONE
# Throws     : Croaks on invalid invocation, and throws any errors word_list()
# Notes      :
# See Also   :
sub print_words{
    my $self = shift;
    
    # validate args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    print join "\n", @{$self->word_list()};
    print "\n";
    
    # final truthy return to keep perlcritic happy
    return 1;
}

1; # because Perl is just a little bit odd :)