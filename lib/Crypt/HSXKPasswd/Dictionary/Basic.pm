package Crypt::HSXKPasswd::Dictionary::Basic;

use parent Crypt::HSXKPasswd::Dictionary;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw(-no_match_vars); # for more readable code
use List::MoreUtils qw(uniq); # for array deduplication
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
# Returns    : An object of type Crypt::HSXKPasswd::Dictionary::Basic
# Arguments  : 1) a string representing a file path to a dictionary file
#                   -- OR --
#                 an array ref containing a list of words
#               2) OPTIONAL - the encoding to import the file with. The default
#                  is UTF-8 (ignored if the first argument is not a file path).
# Throws     : Croaks on invalid invocation and invalid args.
# Notes      : 
# See Also   : 
sub new{
    my $class = shift;
    my $dict_source = shift;
    my $encoding = shift;
    
    # validate the args
    Crypt::HSXKPasswd::_force_class($class, $_CLASS);
    unless(defined $dict_source && (ref $dict_source eq q{} || ref $dict_source eq 'ARRAY')){
        $_MAIN_CLASS->_error('invalid args - first argument must be a path to a dictionary file or an array ref');
    }
    unless($encoding){
        $encoding = 'UTF-8';
    }
    
    # start with a blank object
    my $instance = {
        words => [],
        sources => {
            files => [],
            num_arrays => 0,
        },
    };
    bless $instance, $class;
    
    # try instantiate the word list as appropriate
    $instance->add_words($dict_source, $encoding);
    
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
# Returns    : An object of type Crypt::HSXKPasswd::Dictionary::Basic
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub clone{
    my $self = shift;
    
    # validate the args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    # create an empty object
    my $clone = {
        words => [],
        sources => {
            files => [],
            num_arrays => 0,
        },
    };
    
    # fill in the values
    foreach my $word (@{$self->{words}}){
        push @{$clone->{words}}, $word;
    }
    foreach my $file (@{$self->{sources}->{files}}){
        push @{$clone->{sources}->{files}}, $file;
    }
    $clone->{sources}->{num_arrays} = $self->{sources}->{num_arrays};
    
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
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    # return a reference to the word list
    return $self->{words};
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Override source() from the parent class and return information
#              about the word sources.
# Returns    : An array reference.
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub source{
    my $self = shift;
    
    # validate args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    my $source = $self->SUPER::source();
    if($self->{sources}->{num_arrays} || scalar @{$self->{sources}->{files}}){
        $source .= ' (loaded from: ';
        if($self->{sources}->{num_arrays}){
            $source .= $self->{sources}->{num_arrays}.' array refs';
        }
        if($self->{sources}->{num_arrays} && scalar @{$self->{sources}->{files}}){
            $source .= ' and ';
        }
        if(scalar @{$self->{sources}->{files}}){
            $source .= 'the file(s) '.(join q{, }, @{$self->{sources}->{files}});
        }
        $source .= ')';
    }
    
    return $source;
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Blank the loaded word list.
# Returns    : A reference to self to facilitate function chaining
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub empty{
    my $self = shift;
    
    # validate args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    
    # blank the word list and sources
    $self->{words} = [];
    $self->{sources}->{files} = [];
    $self->{sources}->{num_arrays} = 0;
    
    # return a reference to self
    return $self;
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Load words from a file or array ref, appending them to the word
#              list.
# Returns    : a reference to self to facilitate function chaining
# Arguments  : 1) the path to the file to load words from
#                    --OR--
#                 a reference to an array of words
#               2) OPTIONAL - the encoding to import the file with. The default
#                  is UTF-8 (ignored if the first argument is not a file path).
# Throws     : Croaks on invalid invocation or invalid args. Carps on invalid
#              invalid word.
# Notes      : 
# See Also   :
sub add_words{
    my $self = shift;
    my $dict_source = shift;
    my $encoding = shift;
    
    # validate args
    Crypt::HSXKPasswd::_force_instance($self, $_CLASS);
    unless(defined $dict_source && (ref $dict_source eq q{} || ref $dict_source eq 'ARRAY')){
        $_MAIN_CLASS->_error('invalid args - first argument must be a path to a dictionary file or an array ref');
    }
    unless($encoding){
        $encoding = 'UTF-8';
    }
    
    # try load the words from the relevant source
    my $valid_word_re = qr/^[[:alpha:]]+$/sx;
    my @words = ();
    if(ref $dict_source eq 'ARRAY'){
        # load valid words from the referenced array
        @words = @{$dict_source};
        
        # increase the array source count
        $self->{sources}->{num_arrays}++;
    }else{
        # load the words from a file path
        
        # make sure the file path is valid
        unless(-f $dict_source){
            $_MAIN_CLASS->_error("file $dict_source not found");
        }
        
        # try load and parse the contents of the file
        open my $WORD_FILE_FH, "<:encoding($encoding)", $dict_source or $_MAIN_CLASS->_error("Failed to open $dict_source with error: $OS_ERROR");
        my $word_file_contents = do{local $/ = undef; <$WORD_FILE_FH>};
        close $WORD_FILE_FH;
        LINE:
        foreach my $line (split /\n/sx, $word_file_contents){
            # skip empty lines
            next LINE if $line =~ m/^\s*$/sx;
        
            # skip comment lines
            next LINE if $line =~ m/^[#]/sx;
            
            # if we got here, store the word
            push @words, $line;
        }
        
        # make sure we got at least one word!
        unless(scalar @words){
            $_MAIN_CLASS->_error("file $dict_source contained no valid words");
        }
        
        # add the file to the list of loaded files
        push @{$self->{sources}->{files}}, $dict_source;
    }
    
    # process the words
    foreach my $word (@words){
        if($word && ref $word eq q{} && $word =~ m/$valid_word_re/sx){
            push @{$self->{words}}, "$word";
        }else{
            $_MAIN_CLASS->_warn("Skipping invalid word: $word");
        }
    }
    
    # de-dupe the word list
    my @unique_words = uniq(@{$self->{words}});
    $self->{words} = [@unique_words];
    
    # return a reference to self
    return $self;
}

1; # because Perl is just a little bit odd :)