package Crypt::HSXKPasswd::Dictionary::System;

use parent Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Crypt::HSXKPasswd; # for the error function
use Crypt::HSXKPasswd::Dictionary::Basic; # used to process the dictionary file

# set things up for using UTF-8
use Encode qw(encode decode);
use feature 'unicode_strings';
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
my $_CLASS = 'Crypt::HSXKPasswd::Dictionary::System';
my $_MAIN_CLASS = 'Crypt::HSXKPasswd';

# possible dictionary file locations
my @_DICTIONARY_PATHS = qw(/usr/share/dict/words /usr/dict/words);

#
# --- Constructor -------------------------------------------------------------
#

#####-SUB-#####################################################################
# Type       : CONSTRUCTOR (CLASS)
# Returns    : An object of type Crypt::HSXKPasswd::Dictionary::System
# Arguments  : NONE
# Throws     : Croaks on invalid invocation, or if there is no system
#              dictionary found.
# Notes      : 
# See Also   : 
sub new{
    my $class = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_MAIN_CLASS->_error('invalid invocation of class method');
    }
    
    # try find a dictionary file
    my $dictionary = q{};
    DICTIONARY_PATH:
    foreach my $path (@_DICTIONARY_PATHS){
        if(-f $path){
            $dictionary = $path;
            last DICTIONARY_PATH;
        }
    }
    unless($dictionary){
        $_MAIN_CLASS->_error('no system dictionary found');
    }
    
    # initialise and bless the object
    my $instance = {
        file_path => $dictionary,
        system_dictionary => Crypt::HSXKPasswd::Dictionary::Basic->new($dictionary),
    };
    bless $instance, $class;
    
    # return the object
    return $instance;
}

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Override clone() from the parent class and return a clone of
#              self.
# Returns    : An object of type Crypt::HSXKPasswd::Dictionary::System
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub clone{
    my $self = shift;
    
    # validate the args
    unless(defined $self && $self->isa($_CLASS)){
        $_MAIN_CLASS->_error('invalid invocation of an instance method');
    }
    
    # initialise the clone
    my $clone = {
        file_path => $self->{file_path},
        system_dictionary => $self->{system_dictionary}->clone(),
    };
    
    # bless the clone
    bless $clone, $_CLASS;
    
    # return the clone
    return $clone;
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Override word_list() from the parent class and return the word
#              list.
# Returns    : An array reference.
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub word_list{
    my $self = shift;
    
    # validate the args
    unless(defined $self && $self->isa($_CLASS)){
        $_MAIN_CLASS->_error('invalid invocation of an instance method');
    }
    
    # return a reference to the word list
    return $self->{system_dictionary}->word_list();
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Override source() from the parent class and return information
#              about the word source.
# Returns    : An array reference.
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub source{
    my $self = shift;
    
    # validate args
    unless(defined $self && $self->isa($_CLASS)){
        $_MAIN_CLASS->_error('invalid invocation of instance method');
    }
    
    my $source = $self->SUPER::source();
    $source .= ' ('.$self->{file_path}.')';
    
    return $source;
}

1; # because Perl is just a little bit odd :)