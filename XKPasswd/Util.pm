package XKPasswd::Util;

use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code
use lib '../'; # to keep Komodo edit happy while programming
use XKPasswd;

# conitionally load optional modules
my $JSON_AVAILABLE = 0;
eval{
    require JSON;
    $JSON_AVAILABLE = 1;
};

# Copyright (c) 2014, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# ../XKPasswd.pm)

#
# === NOTE=====================================================================
# This module is not needed to use XKPasswd.pm, it merely contains utility
# functions that are useful during development.
#

#==============================================================================
# Code
#==============================================================================

#
# 'Constants'------------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.1_01');

# utility variables
my $_CLASS = 'XKPasswd::Util';

#
# Public Class (Static) functions ---------------------------------------------
#

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Test all presets defined in the XKPasswd module for validity and
#              against a given dictionary file for sufficient enthropy
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. the path to a dictionary file
# Throws     : Croaks on invalid invocation or args, or if there is a problem
#              testing the configs
# Notes      :
# See Also   :
sub test_presets{
    my $class = shift;
    my $dict_path = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $dict_path && -f $dict_path){
        XKPasswd->_error('invalid args, must pass a dictionary file path');
    }
    
    # get the list of config names from the parent
    my @preset_names = XKPasswd->defined_presets();
    print 'INFO - found '.(scalar @preset_names).' presets ('.(join q{, }, @preset_names).")\n";
    
    # first test the validity of all preset configs
    print "\nINFO - testing preset config validity\n";
    XKPasswd->_check_presets();
    print "INFO - Done testing config validity\n";
    
    # then test each config for sufficient entropy by instantiating an instance with each one
    print "\nINFO - testing preset config + dictionary entropy\n";
    foreach my $preset (@preset_names){
        print "Testing '$preset'\n";
        my $xkpasswd = XKPasswd->new($dict_path, $preset);
        my %stats = $xkpasswd->stats();
        print "$preset: TOTAL WORDS=$stats{dictionary_words_total}, AVAILABLE WORDS=$stats{dictionary_words_filtered} ($stats{dictionary_words_percent_avaialable}%)";
        print 'RESTRICTIONS: ';
        if($stats{dictionary_filter_length_min} == $stats{dictionary_filter_length_max}){
            print "length=$stats{dictionary_filter_length_min}\n";
        }else{
            print "$stats{dictionary_filter_length_min}>=length<=$stats{dictionary_filter_length_max}\n";
        }
        print "$preset: BLIND=$stats{password_entropy_blind_min} (need $XKPasswd::ENTROPY_MIN_BLIND), SEEN=$stats{password_entropy_seen} (need $XKPasswd::ENTROPY_MIN_SEEN)\n";
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
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub print_preset_samples{
    my $class = shift;
    my $dict_path = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $dict_path && -f $dict_path){
        XKPasswd->_error('invalid args, must pass a dictionary file path');
    }
    
    foreach my $preset (XKPasswd->defined_presets()){
        print "$preset: ".xkpasswd($dict_path, $preset)."\n";
    }
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Convert a JSON string into an XKPasswd config hashref
# Returns    : an XKPasswd config hashref
# Arguments  : 1. the JSON string as a scalar
# Throws     : Croaks on invalid invocation, invalid args, invalid config, and
#              if the JSON module is not available
# Notes      : Since you can't send code refs via JSON, the random function
#              in all hashrefs is set to the default value
# See Also   :
sub config_from_json{
    my $class = shift;
    my $json_string = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $json_string && ref $json_string eq q{} && length $json_string){
        XKPasswd->_error('invalid args, must pass a JSON string');
    }
    
    # make sure the JSON module is available
    unless($JSON_AVAILABLE){
        XKPasswd->_error(q{Perl JSON module not avaialble, and required for this function});
    }
    
    # try parse the passed string
    my $loaded_config = JSON->new->utf8->decode($json_string);
    unless($loaded_config){
        XKPasswd->_error('Failed to parse JSON string');
    }
    
    # set the ranom generator to the default value (can't sned code refs via JSON)
    $loaded_config->{random_function} = \&XKPasswd::basic_random_generator;
    
    # make sure the config is valid
    eval{
        XKPasswd->is_valid_config($loaded_config, 'do_croak'); # returns 1 on success
    }or do{
        XKPasswd->_error("Config failed to validate with error: $EVAL_ERROR");
    };
    
    # return the config
    return $loaded_config;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Generate n passwords and return them, and the entropy stats as a
#              JSON string.
# Returns    : A JSON string as a scalar representing a hashref contianing an
#              array of passwords indexed by 'passwords', and a hashref of
#              entropy stats indexed by 'stats'. The stats hashref itself is
#              indexed by: 'password_entropy_blind',
#              'password_permutations_blind', 'password_entropy_blind_min',
#              'password_entropy_blind_max', 'password_permutations_blind_max',
#              'password_entropy_seen' & 'password_permutations_seen'
# Arguments  : 1. an XKPasswd object
#              2. the number of passwords to generate
# Throws     : Croaks on invalid invocation, invalid args, if there is a
#              problem generating the passwords, statistics, or converting the
#              results to a JSON string, or if the JSON module is not
#              available.
# Notes      : 
# See Also   :
sub passwords_json{
    my $class = shift;
    my $xkpasswd = shift;
    my $num = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $xkpasswd && $xkpasswd->isa('XKPasswd')){
        XKPasswd->_error('invalid args, must pass an XKPasswd object as the first arg');
    }
    unless(defined $num && ref $num eq q{} && $num =~ m/^\d+$/sx){
        XKPasswd->_error('invalid args, must pass the number of passwords to generate as the second arg');
    }
    
    # make sure the JSON module is available
    unless($JSON_AVAILABLE){
        XKPasswd->_error(q{Perl JSON module not avaialble, and required for this function});
    }
    
    # try generate the passwords and stats - could croak
    my @passwords = $xkpasswd->passwords($num);
    my %stats = $xkpasswd->stats();
    
    # generate the hashref containing the results
    my $responseObj = {
        passwords => [@passwords],
        stats => {
            password_entropy_blind => $stats{password_entropy_blind},
            password_permutations_blind => XKPasswd->_render_bigint($stats{password_permutations_blind}),
            password_entropy_blind_min => $stats{password_entropy_blind_min},
            password_permutations_blind_min => XKPasswd->_render_bigint($stats{password_permutations_blind_min}),
            password_entropy_blind_max => $stats{password_entropy_blind_max},
            password_permutations_blind_max => XKPasswd->_render_bigint($stats{password_permutations_blind_max}),
            password_entropy_seen => $stats{password_entropy_seen},
            password_permutations_seen => XKPasswd->_render_bigint($stats{password_permutations_seen}),
        },
    };
    
    # try generate the JSON string to return
    my $json_string = q{};
    eval{
        $json_string = JSON->new()->encode($responseObj);
        1; # ensure truthy evaluation on succesful execution
    }or do{
        XKPasswd->_error('failed to render hashref as JSON string with error: $EVAL_ERROR');
    };
    
    # return the JSON string
    return $json_string;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Resturn the presets defined in the XKPasswd module as a JSON
#              string
# Returns    : A JSON String as a scalar. The JSON string represets a hashref
#              with three keys  - 'defined_keys' contains an array of preset
#              identifiers, 'presets' contains the preset configs indexed by
#              preset identifier, and 'preset_descriptions' contains the a 
#              hashref of descriptions indexed by preset identifiers
# Arguments  : NONE
# Throws     : Croaks on invalid invocation, if the JSON module is not
#              available, or if there is a problem converting the objects to
#              JSON
# Notes      :
# See Also   :
sub presets_json{
    my $class = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    
    # make sure the JSON module is available
    unless($JSON_AVAILABLE){
        XKPasswd->_error(q{Perl JSON module not avaialble, and required for this function});
    }
    
    # assemble an object cotaining the presets with any keys that can't be
    #  converted to JSON removed
    my @defined_presets = XKPasswd->defined_presets();
    my $sanitised_presets = {};
    my $preset_descriptions = {};
    foreach my $preset_name (@defined_presets){
        $sanitised_presets->{$preset_name} = XKPasswd->preset_config($preset_name);
        $sanitised_presets->{$preset_name}->{random_function} = undef;
        $sanitised_presets->{$preset_name}->{random_increment} = undef;
        $preset_descriptions->{$preset_name} = XKPasswd->preset_description($preset_name);
    }
    my $return_object = {
        defined_presets => [@defined_presets],
        presets => $sanitised_presets,
        preset_descriptions => $preset_descriptions,
    };
    
    # try convert the object to a JSON string
    my $json_string = q{};
    eval{
        $json_string = JSON->new()->encode($return_object);
        1; # ensure truthy evaluation on succesful execution
    }or do{
        XKPasswd->_error("failed to render presets as JSON string with error: $EVAL_ERROR");
    };
    
    # return the JSON string
    return $json_string;
}

1; # because perl is a bit special