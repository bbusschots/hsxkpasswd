package Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Scalar::Util qw( blessed ); # for checking if a reference is blessed
use List::MoreUtils qw( uniq ); # for array deduplication
use Readonly; # for truly constant constants
use Types::Standard qw( :types slurpy ); # for data validation
use Type::Params qw( compile ); # for argument valdiation
use Crypt::HSXKPasswd::Types qw( :types ); # for data validation
use Crypt::HSXKPasswd::Helper; # exports utility functions like _error & _warn

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw( encode decode );
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

# Copyright (c) 2015, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# HSXKPasswd.pm)

#
# === Constants & Package Vars ================================================#
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
    _error("$_CLASS must be extended to be used, and the function clone() must be overridden");
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
    _error("$_CLASS must be extended to be used, and the function word_list() must be overridden");
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
    _force_instance($self);
    
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
    _force_instance($self);
    
    print join "\n", @{$self->word_list()};
    print "\n";
    
    # final truthy return to keep perlcritic happy
    return 1;
}

#
# === Public Class Functions ==================================================#
#

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Distil an array of strings down to a de-duplicated array of only
#              the valid words.
# Returns    : An array of words
# Arguments  : 1) A reference to an array of strings
#              2) OPTIONAL - a named argument warn with a value of 0 or 1. If 1
#                 is passed, warnings will be issued each time an invalid string
#                 is skipped over.
# Throws     : Croaks on invalid invocation or args, and warns on request when
#              skipping words.
# Notes      :
# See Also   :
sub distil_to_words{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(ArrayRef[Str], slurpy Dict[warn => Optional[TrueFalse]]);
    my ($array_ref, $options) = $args_check->(@args);
    my $warn = $options->{warn} || 0;
    
    # loop through the array and copy all valid words to a new array
    my @valid_words = ();
    foreach my $potential_word (@{$array_ref}){
        if(Word->check($potential_word)){
            push @valid_words, $potential_word;
        }else{
            if($warn || _do_debug()){
                my $msg = 'skipping invalid word: '.Word->get_message($potential_word);
                if($warn){
                    _warn($msg);
                }else{
                    _debug($msg);
                }
            }
        }
    }
    
    # de-dupe the valid words
    my @final_words = uniq(@valid_words);
    
    # return the valid words
    return @final_words;
}

1; # because Perl is just a little bit odd :)