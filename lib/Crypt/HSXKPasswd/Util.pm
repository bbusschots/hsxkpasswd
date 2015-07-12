package Crypt::HSXKPasswd::Util;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use DateTime; # for generating timestamps
use Readonly; # for truly constant constants
use Scalar::Util qw(blessed); # for checking if a reference is blessed
use Type::Tiny; # for creating anonymous type constraints
use Type::Params qw( compile ); # for parameter validation with Type::Tiny objects
use Types::Standard qw( :types ); # for basic type checking (Int Str etc.)
use Crypt::HSXKPasswd::Types qw( :types ); # for custom type checking
use Crypt::HSXKPasswd::Helper; # exports utility functions like _error & _warn
use Crypt::HSXKPasswd;

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
# --- Constants ----------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.3');

# utility variables
Readonly my $_CLASS => __PACKAGE__;
Readonly my $_MAIN_CLASS => 'Crypt::HSXKPasswd';

#
# --- Static Class Functions --------------------------------------------------
#

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Test all presets defined in the Crypt::HSXKPasswd module for 
#              avalidity and for sufficient enthropy against a given dictionary
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. An instance of a class that extends
#                 Crypt::HSXKPasswd::Dictionary
# Throws     : Croaks on invalid invocation or args, or if there is a problem
#              testing the configs
# Notes      : This function can be called as a perl one-liner, e.g.
#              perl -C -Ilib -MCrypt::HSXKPasswd::Util -MCrypt::HSXKPasswd::Dictionary::EN -e 'Crypt::HSXKPasswd::Util->test_presets(Crypt::HSXKPasswd::Dictionary::EN->new())'
# See Also   :
sub test_presets{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(InstanceOf['Crypt::HSXKPasswd::Dictionary']);
    my ($dictionary) = $args_check->(@args);
    
    # get the list of config names from the parent
    my @preset_names = $_MAIN_CLASS->defined_presets();
    print 'INFO - found '.(scalar @preset_names).' presets ('.(join q{, }, @preset_names).")\n";
    
    # first test the validity of all preset configs
    print "\nINFO - testing preset config validity\n";
    $_MAIN_CLASS->_check_preset_definitions();
    print "INFO - Done testing config validity\n";
    
    # then test each config for sufficient entropy by instantiating an instance with each one
    print "\nINFO - testing preset config + dictionary entropy\n";
    foreach my $preset (@preset_names){
        print "Testing '$preset'\n";
        my $hsxkpasswd = $_MAIN_CLASS->new(preset => $preset, dictionary => $dictionary);
        my %stats = $hsxkpasswd->stats();
        print "$preset: TOTAL WORDS=$stats{dictionary_words_total}, AVAILABLE WORDS=$stats{dictionary_words_filtered} ($stats{dictionary_words_percent_available}%), ";
        print 'RESTRICTIONS: ';
        if($stats{dictionary_filter_length_min} == $stats{dictionary_filter_length_max}){
            print "length=$stats{dictionary_filter_length_min}\n";
        }else{
            print "$stats{dictionary_filter_length_min}>=length<=$stats{dictionary_filter_length_max}\n";
        }
        print "$preset: BLIND=$stats{password_entropy_blind_min} (need ".Crypt::HSXKPasswd->module_config('ENTROPY_MIN_BLIND')."), SEEN=$stats{password_entropy_seen} (need ".Crypt::HSXKPasswd->module_config('ENTROPY_MIN_SEEN').")\n";
    }
    print "INFO - Done testing entropy\n";
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Generate a sample password with each preset with a given
#              dictionary file
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1) An instance of a class that extends
#                 Crypt::HSXKPasswd::Dictionary
# Throws     : Croaks on invalid invocation
# Notes      : perl -C -Ilib -MCrypt::HSXKPasswd::Util -MCrypt::HSXKPasswd::Dictionary::EN -e 'Crypt::HSXKPasswd::Util->print_preset_samples(Crypt::HSXKPasswd::Dictionary::EN->new())'
# See Also   :
sub print_preset_samples{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(InstanceOf['Crypt::HSXKPasswd::Dictionary']);
    my ($dictionary) = $args_check->(@args);
    
    # loop through each preset and print a sample
    foreach my $preset ($_MAIN_CLASS->defined_presets()){
        print "$preset: ".hsxkpasswd(preset => $preset, dictionary => $dictionary)."\n";
    }
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Sanitise a dictionary file, stripping out invalid words and
#              sorting it alphabetically. The sanitised dictionary is printed to
#              STDOUT in UTF-8.
# Returns    : 1 (to keep perlcritic happy)
# Arguments  : 1. a file path
#              2. OPTIONAL - the encoding to use when reading the file
# Throws     : Croaks on invalid invocation, invalid args and IO error
# Notes      : This function can be called as a perl one-liner, e.g.
#              perl -C -Ilib -MCrypt::HSXKPasswd::Util -e 'Crypt::HSXKPasswd::Util->sanitise_dictionary_file("sample_dict_EN.txt")'
# See Also   :
sub sanitise_dictionary_file{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(Str, Optional[Maybe[Str]]);
    my ($file_path, $encoding) = $args_check->(@args);
    
    # set defaults
    $encoding = 'UTF-8' unless $encoding;
    
    # try load the words from the file
    my @words = ();
    eval{
        # slurp the file
        open my $WORDS_FH, "<:encoding($encoding)", $file_path or croak("Failed to open $file_path with error: $OS_ERROR");
        my $words_file_contents = do{local $/ = undef; <$WORDS_FH>};
        close $WORDS_FH;
        
        # process the content
        my @lines = split /\n/sx, $words_file_contents;
        WORD_FILE_LINE:
        foreach my $line (@lines){
            # skip comment lines
            next if $line =~ m/^[#]/sx;
            
            # skip non-word lines
            next unless $line =~ m/^[[:alpha:]]+$/sx;
            
            # skip words shorter than 4 characters
            next unless $_MAIN_CLASS->_grapheme_length($line) >= 4;
            
            # save word
            push @words, $line;
        }
        
        # ensure there are at least some words
        unless(scalar @words){
            croak("no valid words found in the file $file_path");
        }
        
        1; # ensure truthy evaluation on successful execution
    }or do{
        _error("failed to load words with error: $EVAL_ERROR");
    };
    
    # sort and print the words
    foreach my $word (sort @words){
        print "$word\n";
    }
    
    # explicit return
    return 1;
}

#####-SUB-#####################################################################
# Type       : CLASS
# Purpose    : Generate a Dictionary module from a text file. The function
#              returns the code for the module as a string.
# Returns    : a string.
# Arguments  : 1) the full name of the module to generate.
#              2) the path to the dictionary file.
#              3) OPTIONAL - the encoding of the text file - defaults to UTF-8
#              4) OPTIONAL - the version string to include at the top of of the
#                 generated code - defaults to the same as Crypt::HSXKPasswd.
# Throws     : Croaks on invalid args or file IO error
# Notes      : This function can be called as a perl one-liner, e.g.
#              perl -C -Ilib -MCrypt::HSXKPasswd::Util -e 'Crypt::HSXKPasswd::Util->dictionary_from_text_file("EN_Default", "sample_dict_EN.txt")' > lib/Crypt/HSXKPasswd/Dictionary/EN_Default.pm
#              Also note that words shorter than 4 letters are skipped.
# See Also   :
sub dictionary_from_text_file{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(
        PerlPackageName,
        Str,
        Optional[Maybe[Str]],
        Optional[Maybe[Str]],
    );
    my ($pkg_name, $file_path, $encoding, $version) = $args_check->(@args);
    
    # set defaults
    $encoding = 'UTF-8' unless $encoding;
    $version = $Crypt::HSXKPasswd::VERSION->numify() unless $version;
    
    # try load the words from the file
    my @words = ();
    eval{
        # slurp the file
        open my $WORDS_FH, "<:encoding($encoding)", $file_path or croak("Failed to open $file_path with error: $OS_ERROR");
        my $words_file_contents = do{local $/ = undef; <$WORDS_FH>};
        close $WORDS_FH;
        
        # process the content
        my @lines = split /\r?\n/sx, $words_file_contents;
        WORD_FILE_LINE:
        foreach my $line (@lines){
            # skip comment lines
            next WORD_FILE_LINE if $line =~ m/^[#]/sx;
            
            # skip invalid words
            next WORD_FILE_LINE unless Word->check($line);
            
            # skip words longer than 12 graphemes
            next WORD_FILE_LINE if $_MAIN_CLASS->_grapheme_length($line) > 12;
            
            # save work
            push @words, $line;
        }
        
        # ensure there are at least some words
        unless(scalar @words){
            croak("no valid words found in the file $file_path");
        }
        
        1; # ensure truthy evaluation on successful execution
    }or do{
        _error("failed to load words with error: $EVAL_ERROR");
    };
    
    # generate an ISO 8601 timestamp
    my $iso8601 = DateTime->now()->iso8601().'Z';
    
    # generate the code for the class
    my $pkg_code = <<"END_MOD_START";
package $pkg_name;

use parent ${_MAIN_CLASS}::Dictionary;

# NOTE:
# -----
# This module was Auto-generated at $iso8601 by
# ${_MAIN_CLASS}::Util->dictionary_from_text_file()

# import required modules
use strict;
use warnings;
use English qw( -no_match_vars ); # for more readable code
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use Readonly; # for truly constant constants

# HSXKPasswd stuff
use ${_MAIN_CLASS}::Helper;

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

#
# === Constants ===============================================================#
#

# version info
use version; our \$VERSION = qv('$version');

# utility constants
Readonly my \$_CLASS => '$pkg_name';

# the word list
my \@_WORDS = ( ## no critic (ProhibitQuotedWordLists)
END_MOD_START

    # print the code for the word list
    foreach my $word (@words){
        $pkg_code .= <<"WORD_END";
    '$word',
WORD_END
    }

    $pkg_code .= <<"END_MOD_END";
);

#
# --- Constructor -------------------------------------------------------------
#

#####-SUB-#####################################################################
# Type       : CONSTRUCTOR (CLASS)
# Purpose    : Create a new instance of class $pkg_name
# Returns    : An object of class $pkg_name
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub new{
    my \$class = shift;
    _force_class(\$class);
    my \$instance = {};
    bless \$instance, \$class;
    return \$instance;
}

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-######################################################################
# Type       : INSTANCE or CLASS or SUBROUTINE
# Purpose    : Override clone() from the parent class and return a clone of
#              self.
# Returns    : An object of type $pkg_name
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub clone{
    my \$clone = {};
    bless \$clone, \$_CLASS;
    return \$clone;
}

#####-SUB-#####################################################################
# Type       : INSTANCE or CLASS or SUBROUTINE
# Purpose    : Return the word list.
# Returns    : An Array Ref
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub word_list{
    return [\@_WORDS];
}

1; # because Perl is just a little bit odd :)
END_MOD_END
    
    # return the generated code
    return $pkg_code;
}

1; # because Perl is just a little bit odd :)