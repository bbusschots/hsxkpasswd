package Crypt::HSXKPasswd::Dictionary::System;

use parent Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Readonly; # for truly constant constants
use Crypt::HSXKPasswd::Helper; # exports utility functions like _error & _warn
use Crypt::HSXKPasswd::Dictionary::Basic; # used to process the dictionary file

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

# possible dictionary file locations
Readonly my @_DICTIONARY_PATHS => qw(/usr/share/dict/words /usr/dict/words);

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
    _force_class($class);
    
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
        _error('no system dictionary found');
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
    _force_instance($self);
    
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
    _force_instance($self);
    
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
    _force_instance($self);
    
    my $source = $self->SUPER::source();
    $source .= ' ('.$self->{file_path}.')';
    
    return $source;
}

1; # because Perl is just a little bit odd :)