package Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code
use Crypt::HSXKPasswd; # for the error function

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
my $_CLASS = 'Crypt::HSXKPasswd::Dictionary';
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
sub new{
    $_MAIN_CLASS->_error("$_CLASS must be extended to be used");
}

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A place-holder for the function to get the list of words.
# Returns    : NOTHING - but in subclasses should return an array ref.
# Arguments  : NONE
# Throws     : ALWAYS throws an error to say this class must be extended, and
#              this function must be overridden.
# Notes      :
# See Also   :
sub word_list{
    $_MAIN_CLASS->_error("$_CLASS must be extended to be used, and the function word_list() must be overridden");
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : A function to print out the words in the dictionary
# Returns    : VOID
# Arguments  : NONE
# Throws     : Croaks on invalid invocation, and throws any errors word_list()
# Notes      :
# See Also   :
sub print_words{
    my $self = shift;
    
    # validat args
    unless($self && $self->isa($_CLASS)){
        $_MAIN_CLASS->_error('invalid invocation of instance method');
    }
    
    print join "\n", @{$self->word_list()};
    print "\n";
}