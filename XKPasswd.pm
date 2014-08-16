package XKPasswd;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code
use B qw(svref_2object); # for code ref->name conversion
use Math::Round; # for round()
use Math::BigInt; # for the massive numbers needed to store the permutations

# import (or not) optional modules
my $_CAN_STACK_TRACE = eval{
    require Devel::StackTrace; # for better error reporting when debugging
};

## no critic (ProhibitAutomaticExportation);
use base qw( Exporter );
our @EXPORT = qw( xkpasswd );
## use critic

# Copyright (c) 2014, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# this file)

#==============================================================================
# Code
#==============================================================================

#
# 'Constants'------------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('2.1_01');

# acceptable entropy levels
our $ENTROPY_MIN_BLIND = 78; # 78 bits - equivalent to 12 alpha numeric characters with mixed case and symbols
our $ENTROPY_MIN_SEEN = 52; # 52 bits - equivalent to 8 alpha numeric characters with mixed case and symbols
our $SUPRESS_ENTROPY_WARNINGS = 'NONE'; # valid values are 'NONE', 'ALL', 'SEEN', or 'BLIND' (invalid values treated like 'NONE')

# Logging configuration
our $LOG_STREAM = *STDERR; # default to logging to STDERR
our $LOG_ERRORS = 0; # default to not logging errors
our $DEBUG = 0; # default to not having debugging enabled

# utility variables
my $_CLASS = 'XKPasswd';

# config key definitions
my $_KEYS = {
    symbol_alphabet => {
        req => 0,
        ref => 'ARRAY', # ARRAY REF
        validate => sub { # at least 2 scalar elements
            my $key = shift;
            unless(scalar @{$key} >= 2){ return 0; }
            foreach my $symbol (@{$key}){
                unless(ref $symbol eq q{} && length $symbol == 1){ return 0; }
            }
            return 1;
        },
        desc => 'An array ref containing at least 2 single-character scalars',
    },
    separator_alphabet => {
        req => 0,
        ref => 'ARRAY', # ARRAY REF
        validate => sub { # at least 2 scalar elements
            my $key = shift;
            unless(scalar @{$key} >= 2){ return 0; }
            foreach my $symbol (@{$key}){
                unless(ref $symbol eq q{} && length $symbol == 1){ return 0; }
            }
            return 1;
        },
        desc => 'An array ref containing at least 2 single-character scalars',
    },
    word_length_min => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # int > 3
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key > 3){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer greater than three',
    },
    word_length_max => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # int > 3
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key > 3){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer greater than three',
    },
    num_words => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # an int >= 2
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 2){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to two',
    },
    separator_character => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub {
            my $key = shift;
            unless(length $key == 1 || $key =~ m/^(NONE)|(RANDOM)$/sx){ return 0; }
            return 1;
        },
        desc => q{A scalar containing a single character, or the special value 'NONE' or 'RANDOM'},
    },
    padding_digits_before => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # an int >= 0
            my $key = shift;
            unless($key =~ m/^\d+$/sx){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to zero',
    },
    padding_digits_after => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # an int >= 0
            my $key = shift;
            unless($key =~ m/^\d+$/sx){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to zero',
    },
    padding_type => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub {
            my $key = shift;
            unless($key =~ m/^(NONE)|(FIXED)|(ADAPTIVE)$/sx){ return 0; }
            return 1;
        },
        desc => q{A scalar containg one of the values 'NONE', 'FIXED', or 'ADAPTIVE'},
    },
    padding_characters_before => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub { # positive integer or 0
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 0){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to one',
    },
    padding_characters_after => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub { # positive integer or 0
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 0){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to one',
    },
    pad_to_length => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub { # positive integer >= 12
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 12){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to twelve',
    },
    padding_character => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub {
            my $key = shift;
            unless(length $key == 1 || $key =~ m/^(NONE)|(RANDOM)|(SEPARATOR)$/sx){return 0; }
            return 1;
        },
        desc => q{A scalar containing a single character or one of the special values 'NONE', 'RANDOM', or 'SEPARATOR'},
    },
    case_transform => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub {
            my $key = shift;
            ## no critic (ProhibitComplexRegexes);
            unless($key =~ m/^(NONE)|(UPPER)|(LOWER)|(CAPITALISE)|(INVERT)|(ALTERNATE)|(RANDOM)$/sx){ return 0; }
            ## use critic
            return 1;
        },
        desc => q{A scalar containing one of the values 'NONE' , 'UPPER', 'LOWER', 'CAPITALISE', 'INVERT', 'ALTERNATE', or 'RANDOM'},
    },
    random_function => {
        req => 1,
        ref => q{CODE}, # Code ref
        validate => sub {
            return 1; # no validation to do other than making sure it's a code ref
        },
        desc => q{A code ref to a function for generating n random numbers between 0 and 1},
    },
    random_increment => {
        req => 1,
        ref => q{}, # SCALAR
        validate => sub { # positive integer >= 1, or 'AUTO'
            my $key = shift;
            unless(($key =~ m/^\d+$/sx && $key >= 1) || $key eq 'AUTO'){ return 0; }
            return 1;
        },
        desc => q{A scalar containing an integer value greater than or equal to one, or 'AUTO'},
    },
    character_substitutions => {
        req => 1,
        ref => 'HASH', # Hashref REF
        validate => sub {
            my $key = shift;
            foreach my $char (keys %{$key}){
                unless(ref $char eq q{} && $char =~ m/^\w$/sx){ return 0; } # single char key
                unless(ref $key->{$char} eq q{} && $key->{$char} =~ m/^\S+$/sx){ return 0; }
            }
            return 1;
        },
        desc => 'An hash ref mapping characters to replace with their replacements - can be empty',
    },
};

# preset definitions
my $_PRESETS = {
    DEFAULT => {
        description => 'The default preset resulting in a password consisting of 4 random words of between 4 and 8 letters separated by a random character, with two random digits before and after, and padded with two random characters front and back',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * - _ + = : | ~ ?}],
            word_length_min => 4,
            word_length_max => 8,
            num_words => 4,
            separator_character => 'RANDOM',
            padding_digits_before => 2,
            padding_digits_after => 2,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 2,
            padding_characters_after => 2,
            case_transform => 'CAPITALISE',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 'AUTO',
            character_substitutions => {},
        },
    },
    WEB32 => {
        description => q{A preset for websites that allow passwords up to 32 characteres long.},
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
            separator_alphabet => [qw{- + = . * _ | ~}, q{,}],
            word_length_min => 4,
            word_length_max => 5,
            num_words => 4,
            separator_character => 'RANDOM',
            padding_digits_before => 2,
            padding_digits_after => 2,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 1,
            padding_characters_after => 1,
            case_transform => 'ALTERNATE',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 10,
            character_substitutions => {},
        },
    },
    WEB16 => {
        description => 'A preset for websites that insit passwords not be longer than 16 characters.',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
            separator_alphabet => [qw{- + = . * _ | ~}, q{,}],
            word_length_min => 4,
            word_length_max => 4,
            num_words => 3,
            separator_character => 'RANDOM',
            padding_digits_before => 0,
            padding_digits_after => 0,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 1,
            padding_characters_after => 1,
            case_transform => 'RANDOM',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 8,
            character_substitutions => {},
        },
    },
    WIFI => {
        description => 'A preset for generating 63 character long WPA2 keys (most routers allow 64 characters, but some only 63, hence the odd length).',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
            separator_alphabet => [qw{- + = . * _ | ~}, q{,}],
            word_length_min => 4,
            word_length_max => 8,
            num_words => 6,
            separator_character => 'RANDOM',
            padding_digits_before => 4,
            padding_digits_after => 4,
            padding_type => 'ADAPTIVE',
            padding_character => 'RANDOM',
            pad_to_length => 63,
            case_transform => 'RANDOM',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 22,
            character_substitutions => {},
        },
    },
    APPLEID => {
        description => 'A preset respecting the many prerequisites Apple places on Apple ID passwords. The preset also limits itself to symbols found on the iOS letter and number keyboards (i.e. not the awkward to reach symbol keyboard)',
        config => {
            symbol_alphabet => [qw{! ? @ &}],
            separator_alphabet => [qw{- : .}, q{,}],
            word_length_min => 5,
            word_length_max => 7,
            num_words => 3,
            separator_character => 'RANDOM',
            padding_digits_before => 2,
            padding_digits_after => 2,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 1,
            padding_characters_after => 1,
            case_transform => 'RANDOM',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 12,
            character_substitutions => {},
        },
    },
    NTLM => {
        description => 'A preset for 14 character Windows NTLMv1 password. WARNING - only use this preset if you have to, it is too short to be acceptably secure and will always generate entropy warnings for the case where the config and dictionary are known.',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
            separator_alphabet => [qw{- + = . * _ | ~}, q{,}],
            word_length_min => 5,
            word_length_max => 5,
            num_words => 2,
            separator_character => 'RANDOM',
            padding_digits_before => 1,
            padding_digits_after => 0,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 0,
            padding_characters_after => 1,
            case_transform => 'INVERT',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 5,
            character_substitutions => {},
        },
    },
    SECURITYQ => {
        description => 'A preset for creating fake answers to security questions.',
        config => {
            word_length_min => 4,
            word_length_max => 8,
            num_words => 6,
            separator_character => q{ },
            padding_digits_before => 0,
            padding_digits_after => 0,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            symbol_alphabet => [qw{. ! ?}],
            padding_characters_before => 0,
            padding_characters_after => 1,
            case_transform => 'NONE',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 7,
            character_substitutions => {},
        },
    },
    XKCD => {
        description => 'A preset for generating passwords similar to the example in the original XKCD cartoon, but with a dash to separate the four random words, and the capitalisation randomised to add sufficient entropy to avoid warnings.',
        config => {
            word_length_min => 4,
            word_length_max => 8,
            num_words => 4,
            separator_character => q{-},
            padding_digits_before => 0,
            padding_digits_after => 0,
            padding_type => 'NONE',
            case_transform => 'RANDOM',
            random_function => \&XKPasswd::basic_random_generator,
            random_increment => 8,
            character_substitutions => {},
        },
    },
};

#
# Constructor -----------------------------------------------------------------
#

#####-SUB-######################################################################
# Type       : CONSTRUCTOR (CLASS)
# Purpose    : Instantiate an object of type XKPasswd
# Returns    : An object of type XKPasswd
# Arguments  : 1. The path to a dictionary file
#              2. OPTIONAL - the name of a preset as a scalar (an empty string,
#                 undef, or 'DEFAULT' to get the default config)
#                     -OR-
#                 A hashref containing a full valid config
#              3. OPTIONAL - a hashref continaing any keys from the preset to be
#                 overridden (ignored if a hashref is passed as the second arg)
# Throws     : Croaks if the function is called in an invalid way, or with an
#              invalid config
# Notes      : 
# See Also   : For valid configuarion options see POD documentation below
sub new{
    my $class = shift;
    my $dictionary_path = shift;
    my $preset = shift;
    my $preset_override = shift;
    
    # validate args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of constructor');
    }
    unless(defined $dictionary_path && -f $dictionary_path){
        $_CLASS->_error('a valid dictionary path must be passed as the first argument');
    }
    
    # before going any further, check the presets if debugging (doing later may cause an error before we test)
    if($DEBUG){
        $_CLASS->_check_presets();
    }
    
    # assemble the config hashref
    my $config = {};
    if(defined $preset){
        if(ref $preset eq q{}){
            #we were passed a preset name
            
            # expand blank preset name to 'DEFAULT'
            $preset = 'DEFAULT' if $preset eq q{};
            
            # convert name to caps
            $preset = uc $preset;
            
            # make sure the preset exists
            unless(defined $_PRESETS->{$preset}){
                $_CLASS->_error("invalid arguments - preset '$preset' does not exist");
            }
            
            # if overrides are defined, make sure they are hashrefs
            if(defined $preset_override){
                unless(ref $preset_override eq 'HASH'){
                    $_CLASS->_error('invalid arguments - if present, the third argument must be a hashref');
                }
            }
            
            # load the preset
            $config = $_CLASS->preset_config($preset, $preset_override);
        }elsif(ref $preset eq 'HASH'){
            # we were passed a hashref, so use it as the config
            $config = $preset;
        }else{
            $_CLASS->_error('invalid argument - if present, the second argument must be a scalar or a hashref');
        }
    }else{
        $config = $_CLASS->default_config();
    }
    
    # initialise the object
    my $instance = {
        # 'public' instance variables (none so far)
        # 'PRIVATE' internal variables
        _CONFIG => {},
        _DICTIONARY_PATH => q{}, # the path to the dictionary hashref
        _CACHE_DICTIONARY_FULL => [], # a cache of all words found in the dictionary file
        _CACHE_DICTIONARY_LIMITED => [], # a cache of all the words found in the dictionary file that meet the length criteria
        _CACHE_ENTROPYSTATS => {}, # a cache of the entropy stats for the current combination of dictionary and config
        _CACHE_RANDOM => [], # a cache of random numbers (as floating points between 0 and 1)
        _PASSWORD_COUNTER => 0, # the number of passwords this instance has generated
    };
    bless $instance, $class;
    
    # load the config
    $instance->config($config);
    
    # load the dictionary (can't be done until the config is loaded)
    $instance->dictionary($dictionary_path);
    
    # if debugging, print status
    $_CLASS->_debug("instantiated $_CLASS object with the following details:\n".$instance->status());
    
    # return the initialised object
    return $instance;
}

#
# Public Class (Static) functions ---------------------------------------------
#

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : generate a config hashref populated with the default values
# Returns    : a hashref
# Arguments  : 1. OPTIONAL - a hashref with config keys to over-ride when
#                 assembling the config
# Throws     : Croaks if invoked in an invalid way. If passed overrides also
#              Croaks if the resulting config is invalid, and Carps if passed
#              on each invalid key passed in the overrides hashref.
# Notes      :
# See Also   :
sub default_config{
    my $class = shift;
    my $overrides = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }

    # build and return a default config
    return $_CLASS->preset_config('DEFAULT', $overrides);
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : generate a config hashref populated using a preset
# Returns    : a hashref
# Arguments  : 1. OPTIONAL - The name of the preset to assemble the config for
#                 as a scalar. If no name is passed, the preset 'DEFAULT' is
#                 used
#              2. OPTIONAL - a hashref with config keys to over-ride when
#                 assembling the config
# Throws     : Croaks if invoked in an invalid way. If passed overrides also
#              Croaks if the resulting config is invalid, and Carps if passed
#              on each invalid key passed in the overrides hashref.
# Notes      :
# See Also   :
sub preset_config{
    my $class = shift;
    my $preset = shift;
    my $overrides = shift;
    
    # default blank presets to 'DEFAULT'
    $preset = 'DEFAULT' unless defined $preset;
    
    # convert preset names to upper case
    $preset = uc $preset;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(ref $preset eq q{}){
        $_CLASS->_error('invalid args - if present, the first argument must be a scalar');
    }
    unless(defined $_PRESETS->{$preset}){
        $_CLASS->_error("preset '$preset' does not exist");
    }
    if(defined $overrides){
        unless(ref $overrides eq 'HASH'){
            $_CLASS->_error('invalid args, overrides must be passed as a hashref');
        }
    }
    
    # start by loading the preset
    my $config = $_CLASS->clone_config($_PRESETS->{$preset}->{config});
    
    # if overrides were passed, apply them and validate
    if(defined $overrides){
        foreach my $key (keys %{$overrides}){
            # ensure the key is valid - skip it if not
            unless(defined $_KEYS->{$key}){
                $_CLASS->_warn("Skippining invalid key=$key");
                next;
            }
            
            # ensure the value is valid
            eval{
                $_CLASS->_validate_key($key, $overrides->{$key}, 1); # returns 1 if valid
            }or do{
                $_CLASS->_warn("Skipping key=$key because of invalid value. Expected: $_KEYS->{$key}->{desc}");
                next;
            };
            
            # save the key into the config
            $config->{$key} = $overrides->{$key};
        }
        unless($_CLASS->is_valid_config($config)){
            $_CLASS->_error('The default config combined with the specified overrides has resulted in an inalid config');
        }
    }
    
    # return the config
    return $config;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Clone a config hashref
# Returns    : a hashref
# Arguments  : 1. the config hashref to clone
# Throws     : Croaks if called in an invalid way, or with an invalid config.
# Notes      : This function needs to be updated each time a new non-scalar
#              valid config key is added to the library.
# See Also   :
sub clone_config{
    my $class = shift;
    my $config = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $config && $_CLASS->is_valid_config($config)){
        $_CLASS->_error('invalid args - a valid config hashref must be passed');
    }
    
    # start with a blank hashref
    my $clone = {};
    
    # copy over all the scalar keys
    KEY_TO_CLONE:
    foreach my $key (keys %{$_KEYS}){
        # skip non-scalar keys
        next KEY_TO_CLONE unless $_KEYS->{$key}->{ref} eq q{};
        
        #if the key exists in the config to clone, copy it to the clone
        if(defined $config->{$key}){
            $clone->{$key} = $config->{$key};
        }
    }
    
    # deal with the non-scarlar keys
    if(defined $config->{symbol_alphabet} && ref $config->{symbol_alphabet} eq 'ARRAY'){
        $clone->{symbol_alphabet} = [];
        foreach my $symbol (@{$config->{symbol_alphabet}}){
            push @{$clone->{symbol_alphabet}}, $symbol;
        }
    }
    if(defined $config->{separator_alphabet} && ref $config->{separator_alphabet} eq 'ARRAY'){
        $clone->{separator_alphabet} = [];
        foreach my $symbol (@{$config->{separator_alphabet}}){
            push @{$clone->{separator_alphabet}}, $symbol;
        }
    }
    $clone->{random_function} = $config->{random_function};
    $clone->{character_substitutions} = {};
    foreach my $key (keys %{$config->{character_substitutions}}){
        $clone->{character_substitutions}->{$key} = $config->{character_substitutions}->{$key};
    }
    
    # return the clone
    return $clone;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : validate a config hashref
# Returns    : 1 if the config is valid, 0 otherwise
# Arguments  : 1. a hashref to validate
#              2. OPTIONAL - a true value to throw exception on error
# Throws     : Croaks on invalid args, or on error if second arg is truthy
# Notes      : This function needs to be updated each time a new valid config
#              key is added to the library.
# See Also   :
## no critic (ProhibitExcessComplexity);
sub is_valid_config{
    my $class = shift;
    my $config = shift;
    my $croak = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless($config && ref $config eq 'HASH'){
        $_CLASS->_error('invalid arguments');
    }
    
    #
    # check the keys
    #
    
    my @keys = sort keys %{$_KEYS};
    
    # first ensure all required keys are present
    foreach my $key (@keys){
        # skip non-required keys
        next unless $_KEYS->{$key}->{req};
        
        # make sure the passed config contains the key
        unless(defined $config->{$key}){
            croak("Required key=$key not defined") if $croak;
            return 0;
        }
    }
    
    # next ensure all passed keys have valid values
    foreach my $key (@keys){
        # skip keys not present in the config under test
        next unless defined $config->{$key};
        
        # validate the key
        eval{
            $_CLASS->_validate_key($key, $config->{$key}, 1); # returns 1 on success
        }or do{
            croak("Invalid value for key=$key. Expected: ".$_KEYS->{$key}->{desc}) if $croak;
            return 0;
        };
    }
    
    # finally, make sure all other requirements are met
    
    # if there is a need for a symbol alphabet, make sure one is defined
    if($config->{separator_character} eq 'RANDOM'){
        unless(defined $config->{symbol_alphabet} || defined $config->{separator_alphabet}){
            croak(qq{separator_character='$config->{separator_character}' requires either a symbol_alphabet or separator_alphabet be specified}) if $croak;
            return 0;
        }
    }
    
    # if there is any kind of character padding, make sure a padding character is specified
    if($config->{padding_type} ne 'NONE'){
        unless(defined $config->{padding_character}){
            croak(qq{padding_type='$config->{padding_type}' requires padding_character be set}) if $croak;
            return 0;
        }
        if($config->{padding_character} eq 'RANDOM'){
            unless(defined $config->{symbol_alphabet}){
                croak(qq{padding_character='$config->{padding_character}' requires a symbol_alphabet be specified}) if $croak;
            return 0;
            }
        }
    }
    
    # if there is fixed character padding, make sure before and after are specified, and at least one has a value greater than 1
    if($config->{padding_type} eq 'FIXED'){
        unless(defined $config->{padding_characters_before} && defined $config->{padding_characters_after}){
            croak(q{padding_type='FIXED' requires padding_characters_before & padding_characters_after be set}) if $croak;
            return 0;
        }
        unless($config->{padding_characters_before} + $config->{padding_characters_after} > 0){
            croak(q{padding_type='FIXED' requires at least one of padding_characters_before & padding_characters_after be greater than one (to use no padding use padding_type='NONE')}) if $croak;
            return 0;
        }
    }
    
    # if there is adaptive padding, make sure a length is specified
    if($config->{padding_type} eq 'ADAPTIVE'){
        unless(defined $config->{pad_to_length}){
            croak(q{padding_type='ADAPTIVE' requires pad_to_length be set}) if $croak;
            return 0;
        }
    }
    
    # if we got this far, all is well, so return true
    return 1;
}
## use critic

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Convert a config hashref to a String
# Returns    : A scalar
# Arguments  : 1. A config hashref
# Throws     : Croaks on invalid invocation or with invalid args. Carps if there
#              are problems with the config hashref.
# Notes      :
# See Also   :
sub config_to_string{
    my $class = shift;
    my $config = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $config && ref $config eq 'HASH'){
        $_CLASS->_error('invalid arguments');
    }
    
    # assemble the string to return
    my $ans = q{};
    foreach my $key (sort keys %{$_KEYS}){
        # skip undefined keys
        next unless defined $config->{$key};
        
        # make sure the key has the expected type
        unless(ref $config->{$key} eq $_KEYS->{$key}->{ref}){
            $_CLASS->_warn("unexpected key type for key=$key (expected ref='$_KEYS->{$key}->{ref}', got ref='".ref $config->{$key}.q{')});
            next;
        }
        
        # process the key
        ## no critic (ProhibitCascadingIfElse);
        if($_KEYS->{$key}->{ref} eq q{}){
            # the key is a scalar
            $ans .= $key.q{: '}.$config->{$key}.qq{'\n};
        }elsif($_KEYS->{$key}->{ref} eq 'ARRAY'){
            # the key is an array ref
            $ans .= "$key: [";
            my @parts = ();
            foreach my $subval (sort @{$config->{$key}}){
                push @parts, "'$subval'";
            }
            $ans .= join q{, }, @parts;
            $ans .= "]\n";
        }elsif($_KEYS->{$key}->{ref} eq 'HASH'){
            $ans .= "$key: {";
            my @parts = ();
            foreach my $subkey (sort keys %{$config->{$key}}){
                push @parts, "$subkey: '$config->{$key}->{$subkey}'";
            }
            $ans .= join q{, }, @parts;
            $ans .= "}\n";
        }elsif($_KEYS->{$key}->{ref} eq 'CODE'){
            $ans .= $key.q{: }.$_CLASS->_coderef_to_subname($config->{$key}).qq{\n};
        }else{
            # this should never happen, but just in case, throw a warning
            $_CLASS->_warn("encounterd an un-handled key type ($_KEYS->{$key}->{ref}) for key=$key - skipping key");
        }
        ## use critic
    }
    
    # return the string
    return $ans;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Return a list of all valid preset names
# Returns    : An array of preset names as scalars
# Arguments  : NONE
# Throws     : Croaks on invalid invocation.
# Notes      :
# See Also   :
sub defined_presets{
    my $class = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    # return the preset names
    my @preset_names = sort keys $_PRESETS;
    return @preset_names;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Render the defined presets as a string
# Returns    : A scalar
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub presets_to_string{
    my $class = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    # loop through each preset and assemble the result
    my $ans = q{};
    my @preset_names = $_CLASS->defined_presets();
    foreach my $preset (@preset_names){
        $ans .= $preset."\n===\n";
        $ans .= $_PRESETS->{$preset}->{description}."\n";
        $ans .= "\nConfig:\n---\n";
        $ans .= $_CLASS->config_to_string($_PRESETS->{$preset}->{config});
        $ans .= "\nStatistics:\n---\n";
        my %stats = $_CLASS->config_stats($_PRESETS->{$preset}->{config});
        if($stats{length_min} == $stats{length_max}){
            $ans .= "Length (fixed): $stats{length_min} characters\n";
        }else{
            $ans .= "Length (variable): between $stats{length_min} & $stats{length_max} characters\n";
        }
        $ans .= "Random Numbers Needed Per-Password: $stats{random_numbers_required}\n";
        $ans .= "\n";
    }
    
    # return the string
    return $ans;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Calculate statistics for a given configutration hashref.
# Returns    : A hash of statistics indexed by the following keys:
#              * 'length_min' - the minimum possible length of a password
#                generated by the given config
#              * 'length_max' - the maximum possible length of a password
#                generated by the given config
#              * 'random_numbers_required' - the number of random numbers needed
#                to generate a single password using the given config
# Arguments  : 1. A valid config hashref
#              2. OPTONAL - a truthy value to suppress warnings if the config
#                 is such that there are uncertainties in the calculations.
#                 E.g. the max length is uncertain when the config contains
#                 a character substitution with a replacement of length greater
#                 than 1
# Throws     : Croaks on invalid invocation or args, carps if multi-character
#              substitutions are in use when not using adapive padding
# Notes      : This function ignores character replacements, if one or more
#              multi-character replacements are used when padding is not set
#              to adaptive, this function will return an invalid max length.
# See Also   :
sub config_stats{
    my $class = shift;
    my $config = shift;
    my $suppres_warnings = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $config && $_CLASS->is_valid_config($config)){
        $_CLASS->_error('invalid args - a valid config hashref must be passed');
    }
    
    # calculate the lengths
    my $len_min = 0;
    my $len_max = 0;
    if($config->{padding_type} eq 'ADAPTIVE'){
        $len_min = $len_max = $config->{pad_to_length};
    }else{
        # calcualte the length of everything but the words themselves
        my $len_base = 0;
        if($config->{padding_type} eq 'FIXED'){
            $len_base += $config->{padding_characters_before};
            $len_base += $config->{padding_characters_after};
        }
        if($config->{padding_digits_before} > 0){
            $len_base += $config->{padding_digits_before};
            if($config->{separator_character} ne 'NONE'){
                $len_base++;
            }
        }
        if($config->{padding_digits_after} > 0){
            $len_base += $config->{padding_digits_after};
            if($config->{separator_character} ne 'NONE'){
                $len_base++;
            }
        }
        if($config->{separator_character} ne 'NONE'){
            $len_base += $config->{num_words} - 1;
        }
        
        # maximise and minimise the word lengths to calculate the final answers
        $len_min = $len_base + ($config->{num_words} * $config->{word_length_min});
        $len_max = $len_base + ($config->{num_words} * $config->{word_length_max});
    }
    
    # calculate the number of random numbers needed to generate the password
    my $num_rand = 0;
    $num_rand += $config->{num_words};
    if($config->{case_transform} eq 'RANDOM'){
        $num_rand += $config->{num_words};
    }
    if($config->{separator_character} eq 'RANDOM'){
        $num_rand++;
    }
    if(defined $config->{padding_character} && $config->{padding_character} eq 'RANDOM'){
        $num_rand++;
    }
    $num_rand += $config->{padding_digits_before};
    $num_rand += $config->{padding_digits_after};
    
    # detect whether or not we need to carp about multi-character replacements
    if($config->{padding_type} ne 'ADAPTIVE' && !$suppres_warnings){
        CHAR_SUB:
        foreach my $char (keys %{$config->{character_substitutions}}){
            if(length $config->{character_substitutions}->{$char} > 1){
                $_CLASS->_warn('maximum length calculation is unreliable because the config contains a character substituion with length greater than 1 character');
                last CHAR_SUB;
            }
        }
    }
    
    # assemble the result and return
    my $stats = {
        length_min => $len_min,
        length_max => $len_max,
        random_numbers_required => $num_rand,
    };
    return %{$stats};
}

#
# Public Instance functions ---------------------------------------------------
#

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Get the path to the currently loaded dictionary file, or, load a
#              new dictionary file
# Returns    : A scalar with the path to the loaded dictionary file if called
#              with no argument, or, a reference to the instance (to enable
#              function chaining) if called with a file path
# Arguments  : 1. OPTIONAL - the path to the config file to load as a scalar
# Throws     : Croaks on invalid invocation, or, if there is a problem loading
#              a dictionary file
# Notes      :
# See Also   : For description of dictionary file format, see POD documentation
#              below
sub dictionary{
    my $self = shift;
    my $path = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $path)){
        # we are a getter, so just return
        return $self->{_DICTIONARY_PATH};
    }else{
        # we are a setter, so try load the dictionary
        
        # croak if we are called before the config has been loaded into the instance
        unless(defined $self->{_CONFIG}->{word_length_min} && $self->{_CONFIG}->{word_length_max}){
            $_CLASS->_error('failed to load dictionary file - config has not been loaded yet');
        }
        
        # parse the file
        my @cache_full = $_CLASS->_parse_words_file($path);
    
        # generate the valid word cache - croaks if too few words left after filtering
        my @cache_limited = $_CLASS->_filter_word_list(\@cache_full, $self->{_CONFIG}->{word_length_min}, $self->{_CONFIG}->{word_length_max});
    
        # if we got here all is well, so save the new path and caches into the object
        $self->{_DICTIONARY_PATH} = $path;
        $self->{_CACHE_DICTIONARY_FULL} = [@cache_full];
        $self->{_CACHE_DICTIONARY_LIMITED} = [@cache_limited];
        
        # update the instance's entropy cache
        $self->_update_entropystats_cache();
    }
    
    # return a reference to self
    return 1;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Get a clone of the current config from an instance, or load a
#              new config into the instance.
# Returns    : A config hashref if called with no arguments, or, the instance
#              if called with a hashref (to facilitate function chaining)
# Arguments  : 1. OPTIONAL - a configuartion hashref
# Throws     : Croaks if the function is called in an invalid way, with invalid
#              arguments, or with an invalid config
# Notes      :
# See Also   : For valid configuarion options see POD documentation below
sub config{
    my $self = shift;
    my $config = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $config)){
        # we are a getter - simply return a clone of our config
        return $self._clone_config();
    }else{
        # we are a setter
        
        # ensure the config passed is a hashref
        unless($config && ref $config eq 'HASH'){
            $_CLASS->_error('invalid arguments - the config passed must be a hashref');
        }
        
        # validate the passed config hashref
        eval{
            $_CLASS->is_valid_config($config, 1); # returns 1 if valid
        }or do{
            my $msg = 'invoked with invalid config';
            if($self->{debug}){
                $msg .= " ($EVAL_ERROR)";
            }
            $_CLASS->_error($msg);
        };
        
        # save a clone of the passed config into the instance
        $self->{_CONFIG} = $_CLASS->clone_config($config);
        
        # update the instance's entropy cache
        $self->_update_entropystats_cache();
    }
    
    # return a reference to self to facilitate function chaining
    return $self;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Return the config of the currently running instance as a string.
# Returns    : A scalar.
# Arguments  : NONE
# Throws     : Croaks if invoked in an invalid way. Carps if it meets a key of a
#              type not accounted for in the code.
# Notes      :
# See Also   :
sub config_string{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # assemble the string to return
    my $ans = $_CLASS->config_to_string($self->{_CONFIG});
    
    # return the string
    return $ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Alter the running config with new values.
# Returns    : A reference to the instalce itself to enable function chaining.
# Arguments  : 1. a hashref containing config keys and values.
# Throws     : Croaks on invalid invocaiton, invalid args, and, if the resulting
#              new config is in some way invalid.
# Notes      : Invalid keys in the new keys hashref will be silently ignored.
# See Also   :
sub update_config{
    my $self = shift;
    my $new_keys = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $new_keys && ref $new_keys eq 'HASH'){
        $_CLASS->_error('invalid arguments - the new config keys must be passed as a hashref');
    }
    
    # clone the current config as a starting point for the new config
    my $new_config = $self->_clone_config();
    
    # merge the new values into the config
    my $num_keys_updated = 0;
    foreach my $key (sort keys %{$_KEYS}){
        # skip the key if it's not present in the list of new keys
        next unless defined $new_keys->{$key};
        
        #validate the new key value
        unless($_CLASS->_validate_key($key, $new_keys->{$key})){
            $_CLASS->_error("invalid new value for key=$key");
        }
        
        # update the key in the new config
        $new_config->{$key} = $new_keys->{$key};
        $num_keys_updated++;
        $_CLASS->_debug("updated $key to new value");
    }
    $_CLASS->_debug("updated $num_keys_updated keys");
    
    # validate the merged config
    unless($_CLASS->is_valid_config($new_config)){
        $_CLASS->_error('updated config is invalid');
    }
    
    # re-calculate the dictionary cache if needed
    my @cache_all = @{$self->{_CACHE_DICTIONARY_FULL}};
    my @cache_limited = @{$self->{_CACHE_DICTIONARY_LIMITED}};
    if($new_config->{word_length_min} ne $self->{_CONFIG}->{word_length_min} || $new_config->{word_length_max} ne $self->{_CONFIG}->{word_length_max}){
        # re-build the cache of valid words - throws an error if too few words are returned
        @cache_limited = $_CLASS->_filter_word_list(\@cache_all, $new_config->{word_length_min}, $new_config->{word_length_max});
    }
    
    # if we got here, all is well with the new config, so add it and the caches to the instance
    $self->{_CONFIG} = $new_config;
    $self->{_CACHE_DICTIONARY_LIMITED} = [@cache_limited];
    
    # update the instance's entropy cache
    $self->_update_entropystats_cache();
    
    # return a reference to self
    return $self;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Return the status of the internal caches within the instnace.
# Returns    : A string
# Arguments  : NONE
# Throws     : Croaks in invalid invocation
# Notes      :
# See Also   :
sub caches_state{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }

    # generate the string
    my $ans = q{};
    $ans .= 'Loaded Words: '.(scalar @{$self->{_CACHE_DICTIONARY_LIMITED}}).' (out of '.(scalar @{$self->{_CACHE_DICTIONARY_FULL}}).' loaded from the file)'.qq{\n};
    $ans .= 'Cached Random Numbers: '.(scalar @{$self->{_CACHE_RANDOM}}).qq{\n};
    
    # return it
    return $ans;
}

#####-SUB-######################################################################
# Purpose    : Generaete a random password based on the object's loaded config
# Returns    : a passowrd as a scalar
# Arguments  : NONE
# Throws     : Croaks on invalid invocation or on error generating the password
# Notes      :
# See Also   :
sub password{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    #
    # Generate the password
    #
    my $password = q{};
    eval{
        #
        # start by generating the needed parts of the password
        #
        $_CLASS->_debug('starting to generate random words');
        my @words = $self->_random_words();
        $_CLASS->_debug('got random words='.(join q{, }, @words));
        $self->_transform_case(\@words);
        $self->_substitute_characters(\@words); # TO DO
        my $separator = $self->_separator();
        $_CLASS->_debug("got separator=$separator");
        my $pad_char = $self->_padding_char($separator);
        $_CLASS->_debug("got pad_char=$pad_char");
        
        #
        # Then assemble the finished password
        #
        
        # start with the words and the separator
        $password = join $separator, @words;
        $_CLASS->_debug("assembled base password: $password");
        
        # next add the numbers front and back
        if($self->{_CONFIG}->{padding_digits_before} > 0){
            $password = $self->_random_digits($self->{_CONFIG}->{padding_digits_before}).$separator.$password;
        }
        if($self->{_CONFIG}->{padding_digits_after} > 0){
            $password = $password.$separator.$self->_random_digits($self->{_CONFIG}->{padding_digits_after});
        }
        $_CLASS->_debug("added random digits (as configured): $password");
        
        
        # then finally add the padding characters
        if($self->{_CONFIG}->{padding_type} eq 'FIXED'){
            # simple fixed padding
            if($self->{_CONFIG}->{padding_characters_before} > 0){
                foreach my $c (1..$self->{_CONFIG}->{padding_characters_before}){
                    $password = $pad_char.$password;
                }
            }
            if($self->{_CONFIG}->{padding_characters_after} > 0){
                foreach my $c (1..$self->{_CONFIG}->{padding_characters_after}){
                    $password .= $pad_char;
                }
            }
        }elsif($self->{_CONFIG}->{padding_type} eq 'ADAPTIVE'){
            # adaptive padding
            my $pwlen = length $password;
            if($pwlen < $self->{_CONFIG}->{pad_to_length}){
                # if the password is shorter than the target length, padd it out
                while((length $password) < $self->{_CONFIG}->{pad_to_length}){
                    $password .= $pad_char;
                }
            }elsif($pwlen > $self->{_CONFIG}->{pad_to_length}){
                # if the password is too long, trim it
                $password = substr $password, 0, $self->{_CONFIG}->{pad_to_length};
            }
        }
        $_CLASS->_debug("added padding (as configured): $password");
        1; # ensure true evaluation on successful execution
    }or do{
        $_CLASS->_error("Failed to generate password with the following error: $EVAL_ERROR");
    };
    
    # increment the passwords generated counter
    $self->{_PASSWORD_COUNTER}++;
    
    # return the finished password
    return $password;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Generate multiple passwords
# Returns    : An array of passwords as scalars
# Arguments  : 1. the number of passwords to generate as a scalar
# Throws     : Croaks on invalid invocation or invalid args
# Notes      :
# See Also   :
sub passwords{
    my $self = shift;
    my $num_pws = shift;
    
    # validate args
    unless(defined $self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $num_pws && ref $num_pws eq q{} && $num_pws =~ m/^\d+$/sx && $num_pws > 0){
        $_CLASS->_error('invalid args - must specify the number of passwords to generate as a positive integer');
    }
    
    # generate the needed passwords
    my @passwords = ();
    my $num_to_do = $num_pws;
    while($num_to_do > 0){
        push @passwords, $self->password(); # could croak
        $num_to_do--;
    }
    
    # return the passwords
    return @passwords;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Return statistics about the instance
# Returns    : A hash of statistics indexed by the following keys:
#              * 'dictionary_path' - the path to the dictionary file the
#                instance is using
#              * 'dictionary_words_total' - the total number of words loaded
#                from the dictionary file
#              * 'dictionary_words_filtered' - the number of words loaded from
#                the dictionary file that meet the lenght criteria set in the
#                loaded config
#              * 'dictionary_words_percent_avaialable' - the percentage of the
#                total dictionary that is avialable for use with the loaded
#                config
#              * 'dictionary_filter_length_min' - the minimum length world
#                permitted by the filter
#              * 'dictionary_filter_length_max' - the maximum length world
#                permitted by the filter
#              * 'password_entropy_blind_min' - the entropy of the shortest
#                password this config can generate from the point of view of a
#                brute-force attacker in bits
#              * 'password_entropy_blind_max' - the entropy of the longest
#                password this config can generate from the point of view of a
#                brute-force attacker in bits
#              * 'password_entropy_blind' - the entropy of the average length
#                of password generated by this configuration from the point of
#                view of a brute-force attacker in bits
#              * 'password_entropy_seen' - the true entropy of passwords
#                generated by this instance assuming the dictionary and config
#                are known to the attacker in bits
#              * 'password_length_min' - the minimum length of passwords
#                generated with this instance's config
#              * 'password_length_max' - the maximum length of passwords
#                generated with this instance's config
#              * 'password_permutations_blind_min' - the number of permutations
#                a brute-froce attacker would have to try to be sure of success
#                on the shortest possible passwords geneated by this instance
#                as a Math::BigInt object
#              * 'password_permutations_blind_max' - the number of permutations
#                a brute-froce attacker would have to try to be sure of success
#                on the longest possible passwords geneated by this instance as
#                a Math::BigInt object
#              * 'password_permutations_blind' - the number of permutations
#                a brute-froce attacker would have to try to be sure of success
#                on the average length password geneated by this instance as a
#                Math::BigInt object
#              * 'password_permutations_seen' - the number of permutations an
#                attacker with a copy of the dictionary and config would need to
#                try to be sure of cracking a password generated by this
#                instance as a Math::BigInt object
#              * 'password_random_numbers_required' - the number of random
#                numbers needed to generate a single password using the loaded
#                config
#              * 'passwords_generated' - the number of passwords this instance
#                has generated
#              * 'randomnumbers_cached' - the number of random numbers
#                currently cached within the instance
#              * 'randomnumbers_cache_increment' - the number of random numbers
#                generated at once to re-plenish the cache when it's empty
#              * 'randomnumbers_generator_function' - the name of the function used to
#                generate random numbers (resoved with _coderef_to_subname())
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      : 
# See Also   : _coderef_to_subname()
sub stats{
    my $self = shift;
    
    # validate args
    unless(defined $self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # create a hash to assemble all the stats into
    my %stats = ();
    
    # deal with the config-specific stats
    my %config_stats = $_CLASS->config_stats($self->{_CONFIG});
    $stats{password_length_min} = $config_stats{length_min};
    $stats{password_length_max} = $config_stats{length_max};
    $stats{password_random_numbers_required} = $config_stats{random_numbers_required};
    
    # deal with the dictionary file
    my %dict_stats = $self->_calcualte_dictionary_stats();
    $stats{dictionary_path} = $self->{_DICTIONARY_PATH};
    $stats{dictionary_words_total} = $dict_stats{num_words_total};
    $stats{dictionary_words_filtered} = $dict_stats{num_words_filtered};
    $stats{dictionary_words_percent_avaialable} = $dict_stats{percent_words_available};
    $stats{dictionary_filter_length_min} = $dict_stats{filter_length_min};
    $stats{dictionary_filter_length_max} = $dict_stats{filter_length_max};
    
    # deal with the entropy stats
    $stats{password_entropy_blind_min} = $self->{_CACHE_ENTROPYSTATS}->{entropy_blind_min};
    $stats{password_entropy_blind_max} = $self->{_CACHE_ENTROPYSTATS}->{entropy_blind_max};
    $stats{password_entropy_blind} = $self->{_CACHE_ENTROPYSTATS}->{entropy_blind};
    $stats{password_entropy_seen} = $self->{_CACHE_ENTROPYSTATS}->{entropy_seen};
    $stats{password_permutations_blind_min} = $self->{_CACHE_ENTROPYSTATS}->{permutations_blind_min};
    $stats{password_permutations_blind_max} = $self->{_CACHE_ENTROPYSTATS}->{permutations_blind_max};
    $stats{password_permutations_blind} = $self->{_CACHE_ENTROPYSTATS}->{permutations_blind};
    $stats{password_permutations_seen} = $self->{_CACHE_ENTROPYSTATS}->{permutations_seen};
    
    # deal with password counter
    $stats{passwords_generated} = $self->{_PASSWORD_COUNTER};
    
    # deal with the random number generator
    $stats{randomnumbers_cached} = scalar @{$self->{_CACHE_RANDOM}};
    $stats{randomnumbers_cache_increment} = $self->{_CONFIG}->{random_increment};
    $stats{randomnumbers_generator_function} = $_CLASS->_coderef_to_subname($self->{_CONFIG}->{random_function});
    
    # return the stats
    return %stats;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Represent the current state of the instance as a string.
# Returns    : Returns a multi-line string as as scalar containing details of the
#              loaded dictionary file, config, and caches
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub status{
    my $self = shift;
    
    # validate args
    unless(defined $self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # assemble the response
    my %stats = $self->stats();
    my $status = q{};
    
    # the dictionary
    $status .= "*DICTIONARY*\n";
    $status .= "File path: $stats{dictionary_path}\n";
    $status .= "# words: $stats{dictionary_words_total}\n";
    $status .= "# words of valid length: $stats{dictionary_words_filtered} ($stats{dictionary_words_percent_avaialable}%)\n";
    
    # the config
    $status .= "\n*CONFIG*\n";
    $status .= $self->config_string();
    
    # the random number cache
    $status .= "\n*RANDOM NUMBER CACHE*\n";
    $status .= "# in cache: $stats{randomnumbers_cached}\n";
    
    # password statistics
    $status .= "\n*PASSWORD STATISTICS*\n";
    if($stats{password_length_min} == $stats{password_length_max}){
        $status .= "Password length: $stats{password_length_max}\n";
        $status .= 'Permutations (brute-force): '.$_CLASS->_render_bigint($stats{password_permutations_blind_max})."\n";
    }else{
        $status .= "Password length: between $stats{password_length_min} & $stats{password_length_max}\n";
        $status .= 'Permutations (brute-force): between '.$_CLASS->_render_bigint($stats{password_permutations_blind_min}).q{ & }.$_CLASS->_render_bigint($stats{password_permutations_blind_max}).q{ (average }.$_CLASS->_render_bigint($stats{password_permutations_blind}).")\n";
    }
    $status .= 'Permutations (given dictionary & config): '.$_CLASS->_render_bigint($stats{password_permutations_seen})."\n";
    if($stats{password_length_min} == $stats{password_length_max}){
        $status .= "Entropy (brute-force): $stats{password_entropy_blind_max}bits\n";
    }else{
        $status .= "Entropy (Brute-Force): between $stats{password_entropy_blind_min}bits and $stats{password_entropy_blind_max}bits (average $stats{password_entropy_blind}bits)\n";
    }
    $status .= "Entropy (given dictionary & config): $stats{password_entropy_seen}bits\n";
    $status .= "Passwords Generated: $stats{passwords_generated}\n";
    
    # debug-only info
    if($DEBUG){
        $status .= "\n*DEBUG INFO*\n";
        if($_CAN_STACK_TRACE){
            $status .= "Devel::StackTrace IS installed\n";
        }else{
            $status .= "Devel::StackTrace is NOT installed\n";
        }
    }
    
    # return the status
    return $status;
}

#
# Regular Subs-----------------------------------------------------------------
#

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : A functional interface to this library (exported)
# Returns    : A random password as a scalar
# Arguments  : 1. The path to a dictionary file
#              2. OPTIONAL - the name of a preset as a scalar (an empty string,
#                 undef, or 'DEFAULT' to get the default config)
#                     -OR-
#                 A hashref containing a full valid config
#              3. OPTIONAL - a hashref continaing any keys from the preset to be
#                 overridden (ignored if a hashref is passed as the second arg)
# Throws     : Croaks on error
# Notes      :
# See Also   :
sub xkpasswd{
    my $dictionary_path = shift;
    my $preset = shift;
    my $preset_override = shift;
    
    # try initialise an xkpasswd object
    my $xkpasswd;
    eval{
        $xkpasswd = $_CLASS->new($dictionary_path, $preset, $preset_override);
        1; # ensure truthy evaliation on successful execution
    } or do {
        $_CLASS->_error("Failed to generate password with the following error: $EVAL_ERROR");
    };
    
    # genereate and return a password - could croak
    return $xkpasswd->password();
}

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : The default random generator function.
# Returns    : An array of random decimal numbers between 0 and 1 as scalars.
# Arguments  : 1. the number of random numbers to generate (must be at least 1)
#              2. OPTIONAL - a truthy value to enable debugging
# Throws     : Croaks on invalid args
# Notes      :
# See Also   :
sub basic_random_generator{
    my $num = shift;
    my $debug = shift;
    
    # validate args
    unless(defined $num && $num =~ m/^\d+$/sx && $num >= 1){
        $_CLASS->_error('invalid args - must request at least 1 password');
    }
    
    # generate the random numbers
    my @ans = ();
    my $num_to_generate = $num;
    while($num_to_generate > 0){
        push @ans, rand;
        $num_to_generate--;
    }
    
    # return the random numbers
    return @ans;
}

#
# 'Private' functions ---------------------------------------------------------
#

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function to log output from the module - SHOULD NEVER BE CALLED
#              DIRECTLY
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. the severity of the message (one of 'DEBUG', 'WARNING', or
#                 'ERROR')
#              2. the message to log
# Throws     : Croaks on invalid invocation
# Notes      : THIS FUNCTION SHOULD NEVER BE CALLED DIRECTLY, but always called
#              via _debug(), _warn(), or _error().
#              This function does not croak on invalid args, it confess with as
#              useful an output as it can.
#              If the function prints output, it will do so to $LOG_STREAM. The
#              severity determines the functions exact behaviour:
#              * 'DEBUG' - message is always printed without a stack trace
#              * 'WARNING' - output is carped, and, if $LOG_ERRORS is true the
#                message is also printed
#              * 'ERROR' - output is confessed if $DEBUG and croaked otherwise.
#                If $LOG_ERRORS is true the message is also printed with a
#                stack trace (the stack trace is omited if Devel::StackTrace) is
#                not installed.
# See Also   : _debug(), _warn() & _error()
## no critic (ProhibitExcessComplexity);
sub _log{
    my $class = shift;
    my $severity = uc shift;
    my $message = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        croak((caller 0)[3].'(): invalid invocation of class method');
    }
    unless(defined $severity && ref $severity eq q{} && length $severity > 1){
        $severity = 'UNKNOWN_SEVERITY';
    }
    unless(defined $message && ref $message eq q{}){
        my $output = 'ERROR - '.(caller 0)[3]."(): invoked with severity '$severity' without message at ".(caller 1)[1].q{:}.(caller 1)[2];
        if($LOG_ERRORS){
            my $log_output = $output;
            if($_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
            }
            print {$LOG_STREAM} $log_output."\n";
        }
        confess($output);
    }
    
    # figure out the correct index for the function that is really responsible
    my $caller_index = 2;
    my $calling_func = (caller 1)[3];
    unless($calling_func =~ m/^$_CLASS[:]{2}((_debug)|(_warn)|(_error))$/sx){
        print {$LOG_STREAM} 'WARNING - '.(caller 0)[3].q{(): invoked directly rather than via _debug(), _warn() or _error() - DO NOT DO THIS!};
        $caller_index++;
    }
    
    # deal with evals
    my $true_caller = q{};
    my @caller = caller $caller_index;
    if(@caller){
        $true_caller = $caller[3];
    }
    my $eval_depth = 0;
    while($true_caller eq '(eval)'){
        $eval_depth++;
        $caller_index++;
        my @next_caller = caller $caller_index;
        if(@next_caller){
            $true_caller = $next_caller[3];
        }else{
            $true_caller = q{};
        }
    }
    if($true_caller eq q{}){
        $true_caller = 'UNKNOWN_FUNCTION';
    }
    
    # deal with the message as appropriate
    my $output = "$severity - ";
    if($eval_depth > 0){
        if($eval_depth == 1){
            $output .= "eval() within $true_caller";
        }else{
            $output .= "$eval_depth deep eval()s within $true_caller";
        }
    }else{
        $output .= $true_caller;
    }
    $output .= "(): $message";
    if($severity eq 'DEBUG'){
        # debugging, so always print and do nothing more
        print {$LOG_STREAM} "$output\n" if $DEBUG;
    }elsif($severity eq 'WARNING'){
        # warning - always carp, but first print if needed
        if($LOG_ERRORS){
            print {$LOG_STREAM} "$output\n";
        }
        carp($output);
    }elsif($severity eq 'ERROR'){
        # error - print if needed, then confess or croak depending on whether or not debugging
        if($LOG_ERRORS){
            my $log_output = $output;
            if($DEBUG && $_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
                print {$LOG_STREAM} "$output\n";
            }
            print {$LOG_STREAM} "$log_output\n";
        }
        if($DEBUG){
            confess($output);
        }else{
            croak($output);
        }
    }else{
        # we have an unknown severity, so assume the worst and confess (also log if needed)
        if($LOG_ERRORS){
            my $log_output = $output;
            if($_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
            }
            print {$LOG_STREAM} "$log_output\n";
        }
        confess($output);
    }
    
    # to keep perlcritic happy
    return 1;
}
## use critic

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function for printing a debug message
# Returns    : Always return 1 (to keep perlcritic happpy)
# Arguments  : 1. the debug message to log
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'DEBUG'
# See Also   : _log()
sub _debug{
    my $class = shift;
    my $message = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    #pass the call on to _log
    return $_CLASS->_log('DEBUG', $message);
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function for issuing a warning
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the warning message to log
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'WARNING'
# See Also   : _log()
sub _warn{
    my $class = shift;
    my $message = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    #pass the call on to _log
    return $_CLASS->_log('WARNING', $message);
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function for throwing an error
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the error message to log
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'ERROR'
# See Also   : _log()
sub _error{
    my $class = shift;
    my $message = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    #pass the call on to _log
    return $_CLASS->_log('ERROR', $message);
}

#####-SUB-######################################################################
# Type       : INSTANCE ('PRIVATE')
# Purpose    : Clone the instance's config hashref
# Returns    : a hashref
# Arguments  : NONE
# Throws     : Croaks if called in an invalid way
# Notes      :
# See Also   :
sub _clone_config{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # build the clone
    my $clone = $_CLASS->clone_config($self->{_CONFIG});
    
    # if, and only if, debugging, validate the cloned config so errors in the
    # cloning code will trigger an exception
    if($self->{debug}){
        eval{
            $_CLASS->is_valid_config($clone, 1); # returns 1 if valid
        }or do{
            $_CLASS->_error('cloning error ('.$EVAL_ERROR.')');
        };
    }
    
    # return the clone
    return $clone;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : validate the value for a single key
# Returns    : 1 if the key is valid, 0 otherwise
# Arguments  : 1. the key to validate the value for
#              2. the value to validate
#              3. OPTIONAL - a true value to croak on invalid value
# Throws     : Croaks if invoked invalidly, or on error if arg 3 is truthy.
#              Also Carps if called with invalid key with a truthy arg 3.
# Notes      :
# See Also   :
sub _validate_key{
    my $class = shift;
    my $key = shift;
    my $val = shift;
    my $croak = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $key && ref $key eq q{} && defined $val){
        $_CLASS->_error('invoked with invalid args');
    }
    
    # make sure the key exists
    unless(defined $_KEYS->{$key}){
        carp("invalid key=$key") if $croak;
        return 0;
    }
    
    # make sure the value is of the correct type
    unless(ref $val eq $_KEYS->{$key}->{ref}){
        croak("invalid type for key=$key. Expected: ".$_KEYS->{$key}->{desc}) if $croak;
        return 0;
    }
    
    # make sure the value passes the validation function for the key
    unless($_KEYS->{$key}->{validate}->($val)){
        croak("invalid value for key=$key. Expected: ".$_KEYS->{$key}->{desc}) if $croak;
        return 0;
    }
    
    # if we got here, all is well, so return 1
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Parse a dictionary file into an array of words.
# Returns    : An array of words as scalars.
# Arguments  : 1. a scalar containing the path to the file to parse
# Throws     : Croaks on invalid invocation, invalid args, and if there is an
#              error reading the file.
# Notes      :
# See Also   :
sub _parse_words_file{
    my $class = shift;
    my $path = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $path && ref $path eq q{} && -f $path){
        $_CLASS->_error('invoked with invalid file path');
    }
    
    # slurp the words file
    open my $WORDSFILE, '<', $path or $_CLASS->_error("failed to open words file at $path");
    my $words_raw = do{local $/ = undef; <$WORDSFILE>};
    close $WORDSFILE;
    
    #loop throuh the lines and build up the word list
    my @ans = ();
    LINE:
    foreach my $line (split /\n/sx, $words_raw){
         # skip empty lines
        next LINE if $line =~ m/^\s*$/sx;
        
        # skip comment lines
        next LINE if $line =~ m/^[#]/sx;
        
        # skip anything that's not at least three letters
        next LINE unless $line =~ m/^[[:alpha:]]{4,}$/sx;
        
        # store the word
        push @ans, $line;
    }
    
    # return the answer
    return @ans;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Filter a word list based on word length
# Returns    : An array of words as scalars.
# Arguments  : 1. a reference to the array of words to filter.
# Throws     : Croaks on invalid invocation, or if too few matching words found.
# Notes      :
# See Also   :
sub _filter_word_list{
    my $class = shift;
    my $word_list_ref = shift;
    my $min_len = shift;
    my $max_len = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $word_list_ref && ref $word_list_ref eq q{ARRAY}){
        $_CLASS->_error('invoked with invalid word list');
    }
    unless(defined $min_len && ref $min_len eq q{} && $min_len =~ m/^\d+$/sx && $min_len > 3){
        $_CLASS->_error('invoked with invalid minimum word length');
    }
    unless(defined $max_len && ref $max_len eq q{} && $max_len =~ m/^\d+$/sx && $max_len >= $min_len){
        $_CLASS->_error('invoked with invalid maximum word length');
    }
    
    #build the array of words of appropriate length
    my @ans = ();
    WORD:
    foreach my $word (@{$word_list_ref}){
        # skip words shorter than the minimum
        next WORD if length $word < $min_len;
        
        # skip words longer than the maximum
        next WORD if length $word > $max_len;
        
        # store the word in the filtered list
        push @ans, $word;
    }
    
    # return the list
    return @ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Generate a random integer greater than 0 and less than a given
#              maximum value.
# Returns    : A random integer as a scalar.
# Arguments  : 1. the min value for the random number (as a positive integer)
# Throws     : Croaks if invoked in an invalid way, with invalid args, of if
#              there is a problem generating random numbers (should the cache)
#              be empty.
# Notes      : The random cache is used as the source for the randomness. If the
#              random pool is empty, this function will replenish it.
# See Also   :
sub _random_int{
    my $self = shift;
    my $max = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $max && $max =~ m/^\d+$/sx && $max > 0){
        $_CLASS->_error('invoked with invalid random limit');
    }
    
    # calculate the random number
    my $ans = ($self->_rand() * 1_000_000) % $max;
    
    # return it
    $_CLASS->_debug("returning $ans (max=$max)");
    return $ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Generate a number of random integers.
# Returns    : A scalar containing a number of random integers.
# Arguments  : 1. The number of random integers to generate
# Throws     : Croaks on invalid invocation, or if there is a problem generating
#              the needed randomness.
# Notes      :
# See Also   :
sub _random_digits{
    my $self = shift;
    my $num = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $num && $num =~ m/^\d+$/sx && $num > 0){
        $_CLASS->_error('invoked with invalid number of digits');
    }
    
    # assemble the response
    my $ans = q{};
    foreach my $n (1..$num){
        $ans .= $self->_random_int(10);
    }
    
    # return the response
    return $ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Return the next random number in the cache, and if needed,
#              replenish it.
# Returns    : A decimal number between 0 and 1
# Arguments  : NONE
# Throws     : Croaks if invoked in an invalid way, or if there is problem
#              replenishing the random cache.
# Notes      :
# See Also   :
sub _rand{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # get the next random number from the cache
    my $num = shift @{$self->{_CACHE_RANDOM}};
    if(!defined $num){
        # the cache was empty - so try top up the random cache - could croak
        $_CLASS->_debug('random cache empty - attempting to replenish');
        $self->_increment_random_cache();
        
        # try shift again
        $num = shift @{$self->{_CACHE_RANDOM}};
    }
    
    # make sure we got a valid random number
    unless(defined $num && $num =~ m/^\d+([.]\d+)?$/sx && $num >= 0 && $num <= 1){
        $_CLASS->_error('found invalid entry in random cache');
    }
    
    # return the random number
    $_CLASS->_debug("returning $num (".(scalar @{$self->{_CACHE_RANDOM}}).' remaining in cache)');
    return $num;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Append random numbers to the cache.
# Returns    : Always returns 1.
# Arguments  : NONE
# Throws     : Croaks if incorrectly invoked or if the random generating
#              function fails to produce random numbers.
# Notes      :
# See Also   :
sub _increment_random_cache{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # figure out how many numbers to generate
    my $num_rand = $self->{_CONFIG}->{random_increment};
    if($num_rand eq 'AUTO'){
        $_CLASS->_debug(q{random_increment='AUTO' - generating stats to determine increment to use});
        my %conf_stats = $_CLASS->config_stats($self->{_CONFIG});
        $num_rand = $conf_stats{random_numbers_required};
        $_CLASS->_debug("using increment of $num_rand");
    }else{
        $_CLASS->_debug("using hard-coded increment of $num_rand");
    }
    
    # genereate the random numbers
    my @random_numbers = &{$self->{_CONFIG}->{random_function}}($num_rand);
    $_CLASS->_debug('generated '.(scalar @random_numbers).' random numbers ('.(join q{, }, @random_numbers).')');
    
    # validate them
    my $num_generated = scalar @random_numbers;
    unless($num_generated == $num_rand){
        $_CLASS->_error("random function did not return the correct number of random numbers (expected $num_rand, got $num_generated)");
    }
    foreach my $num (@random_numbers){
        unless($num =~ m/^1|(0([.]\d+)?)$/sx){
            $_CLASS->_error("random function returned and invalid value ($num)");
        }
    }
    
    # add them to the cache
    foreach my $num (@random_numbers){
        push @{$self->{_CACHE_RANDOM}}, $num;
    }
    
    # always return 1 (to keep PerlCritic happy)
    return 1;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Get the required number of random words from the loaded words
#              file
# Returns    : An array of words
# Arguments  : NONE
# Throws     : Croaks on invalid invocation or error generating random numbers
# Notes      : The number of words generated is determined by the num_words
#              config key.
# See Also   :
sub _random_words{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # get the random words
    my @ans = ();
    $_CLASS->_debug('about to generate '.$self->{_CONFIG}->{num_words}.' words');
    while ((scalar @ans) < $self->{_CONFIG}->{num_words}){
        my $word = $self->{_CACHE_DICTIONARY_LIMITED}->[$self->_random_int(scalar @{$self->{_CACHE_DICTIONARY_LIMITED}})];
        $_CLASS->_debug("generate word=$word");
        push @ans, $word;
    }
    
    # return the list of random words
    $_CLASS->_debug('returning '.(scalar @ans).' words');
    return @ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Get the separator character to use based on the loaded config.
# Returns    : A scalar containing the separator, which could be an empty string.
# Arguments  : NONE
# Throws     : Croaks on invalid invocation, or if there is a problem generating
#              any needed random numbers.
# Notes      : The character returned is controlled by the config variable
#              separator_character
# See Also   :
sub _separator{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # figure out the separator character
    my $sep = $self->{_CONFIG}->{separator_character};
    if ($sep eq 'NONE'){
        $sep = q{};
    }elsif($sep eq 'RANDOM'){
        if(defined $self->{_CONFIG}->{separator_alphabet}){
            $sep = $self->{_CONFIG}->{separator_alphabet}->[$self->_random_int(scalar @{$self->{_CONFIG}->{separator_alphabet}})];
        }else{
            $sep = $self->{_CONFIG}->{symbol_alphabet}->[$self->_random_int(scalar @{$self->{_CONFIG}->{symbol_alphabet}})];
        }
    }
    
    # return the separator character
    return $sep
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Return the padding character based on the loaded config.
# Returns    : A scalar containing the padding character, which could be an
#              empty string.
# Arguments  : 1. the separator character being used to generate the password
# Throws     : Croaks on invalid invocation, or if there is a problem geneating
#              any needed random numbers.
# Notes      : The character returned is determined by a combination of the
#              padding_type & padding_character config variables.
# See Also   :
sub _padding_char{
    my $self = shift;
    my $sep = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $sep){
        $_CLASS->_error('no separator character passed');
    }
    
    # if there is no padding character needed, return an empty string
    if($self->{_CONFIG}->{padding_type} eq 'NONE'){
        return q{};
    }
    
    # if we got here we do need a character, so generate one as appropriate
    my $padc = $self->{_CONFIG}->{padding_character};
    if($padc eq 'SEPARATOR'){
        $padc = $sep;
    }elsif($padc eq 'RANDOM'){
        $padc = $self->{_CONFIG}->{symbol_alphabet}->[$self->_random_int(scalar @{$self->{_CONFIG}->{symbol_alphabet}})];
    }
    
    # return the padding character
    return $padc;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Apply the case transform (if any) specified in the loaded config.
# Returns    : Always returns 1 (to keep PerlCritic happy)
# Arguments  : 1. A reference to the array contianing the words to be
#                 transformed.
# Throws     : Croaks on invalid invocation or if there is a problem generating
#              any needed random numbers.
# Notes      : The transformations applied are controlled by the case_transform
#              config variable.
# See Also   :
## no critic (ProhibitExcessComplexity);
sub _transform_case{
    my $self = shift;
    my $words_ref = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $words_ref && ref $words_ref eq 'ARRAY'){
        $_CLASS->_error('no words array reference passed');
    }
    
    # if the transform is set to nothing, then just return
    if($self->{_CONFIG}->{case_transform} eq 'NONE'){
        return 1;
    }
    
    # apply the appropriate transform
    ## no critic (ProhibitCascadingIfElse);
    if($self->{_CONFIG}->{case_transform} eq 'UPPER'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            $words_ref->[$i] = uc $words_ref->[$i];
        }
    }elsif($self->{_CONFIG}->{case_transform} eq 'LOWER'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            $words_ref->[$i] = lc $words_ref->[$i];
        }
    }elsif($self->{_CONFIG}->{case_transform} eq 'CAPITALISE'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            $words_ref->[$i] = ucfirst lc $words_ref->[$i];
        }
    }elsif($self->{_CONFIG}->{case_transform} eq 'INVERT'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            $words_ref->[$i] = lcfirst uc $words_ref->[$i];
        }
    }elsif($self->{_CONFIG}->{case_transform} eq 'ALTERNATE'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            my $word = $words_ref->[$i];
            if($i % 2 == 0){
                $word = lc $word;
            }else{
                $word = uc $word;
            }
            $words_ref->[$i] = $word;
        }
    }elsif($self->{_CONFIG}->{case_transform} eq 'RANDOM'){
        foreach my $i (0..((scalar @{$words_ref}) - 1)){
            my $word = $words_ref->[$i];
            if($self->_random_int(2) % 2 == 0){
                $word = uc $word;
            }else{
                $word = lc $word;
            }
            $words_ref->[$i] = $word;
        }
    }
    ## use critic
    
    return 1; # just to to keep PerlCritic happy
}
## use critic

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Apply any case transforms specified in the loaded config.
# Returns    : Always returns 1 (to keep PerlCritic happy)
# Arguments  : 1. a reference to an array containing the words that will make up
#                 the password.
# Throws     : Croaks on invalid invocation or invalid args.
# Notes      : The substitutions that will be applied are specified in the
#              character_substitutions config variable.
# See Also   :
sub _substitute_characters{
    my $self = shift;
    my $words_ref = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    unless(defined $words_ref && ref $words_ref eq 'ARRAY'){
        $_CLASS->_error('no words array reference passed');
    }
    
    # if no substitutions are defined, do nothing
    unless(defined $self->{_CONFIG}->{character_substitutions} && (scalar keys %{$self->{_CONFIG}->{character_substitutions}})){
        return 1;
    }
    
    # If we got here, go ahead and apply the substitutions
    foreach my $i (0..(scalar @{$words_ref})){
        my $word = $words_ref->[$i];
        foreach my $char (keys %{$self->{_CONFIG}->{character_substitutions}}){
            my $sub = $self->{_CONFIG}->{character_substitutions}->{$char};
            $word =~ s/$char/$sub/sxg;
        }
        $words_ref->[$i] = $word;
    }
    
    # always return 1 to keep PerlCritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Perform sanity checks on all defined presets
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : NONE
# Throws     : Croaks on invalid input
# Notes      : The function is designed to be called from the constructor when
#              in debug mode. It prints information on what it's doing and any
#              errors it finds to STDERR
# See Also   :
sub _check_presets{
    my $class = shift;
    
    # validate the args
    unless($class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    
    # loop through all presets and perform sanity checks
    my @preset_names = $_CLASS->defined_presets();
    my $num_problems = 0;
    foreach my $preset (@preset_names){
        # make sure the preset is valid
        eval{
            $_CLASS->is_valid_config($_PRESETS->{$preset}->{config}, 1);
            1; # ensure truthy evaluation on success
        }or do{
            $_CLASS->_warn("preset $preset has invalid config ($EVAL_ERROR)");
            $num_problems++;
        };
        
        # make sure the random_increment is optimal
        if($_PRESETS->{$preset}->{config}->{random_increment} ne 'AUTO'){
            my %stats = $_CLASS->config_stats($_PRESETS->{$preset}->{config});
            unless($_PRESETS->{$preset}->{config}->{random_increment} == $stats{random_numbers_required}){
                $_CLASS->_warn("preset $preset has sub-optimal random_increment (value=$_PRESETS->{$preset}->{config}->{random_increment}, required per password=$stats{random_numbers_required})");
                $num_problems++;
            }
        }
    }
    if($num_problems == 0){
        $_CLASS->_debug('all presets OK');
    }
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Gather entropy stats for the combination of the loaded config
#              and dictionary.
# Returns    : A hash of stats indexed by:
#              * 'permutations_blind_min' - the number of permutations to be
#                tested by an attacker with no knowledge of the dictionary file
#                used, or the config used, assuming the minimum possible
#                password length from the given config (as BigInt)
#              * 'permutations_blind_max' - the number of permutations to be
#                tested by an attacker with no knowledge of the dictionary file
#                used, or the cofig file used, assuming the maximum possible
#                password length fom the given config (as BigInt)
#              * 'permutations_blind' - the number of permutations for the
#                average password length for the given config (as BigInt)
#              * 'permutations_seen' - the number of permutations to be tested
#                by an attacker with full knowledge of the dictionary file and
#                configuration used (as BigInt)
#              * 'entropy_blind_min' - permutations_blind_min converted to bits
#              * 'entropy_blind_max' - permutations_blind_max converted to bits
#              * 'entropy_blind' - permutations_blind converted to bits
#              * 'entropy_seen' - permutations_seen converted to bits
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      : This function uses config_stats() to determined the longest and
#              shortest password lengths, so the caveat that function has
#              when it comes to multi-character substitutions applies here too.
#              This function assumes no accented characters (at least for now).
#              For the blind calculations, if any single symbol is present, a
#              search-space of 33 symbols is assumed (same as password
#              haystacks page)
# See Also   : config_stats()
sub _calculate_entropy_stats{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    my %ans = ();
    
    # get the password length details for the config
    my %config_stats = $_CLASS->config_stats($self->{_CONFIG}, 'supress errors');
    my $b_length_min = Math::BigInt->new($config_stats{length_min});
    my $b_length_max = Math::BigInt->new($config_stats{length_max});
    
    # calculate the blind permutations - (based purely on length and alphabet)
    my $alphabet_count = 12; # all passwords have at least one case of letters
    if($self->{_CONFIG}->{case_transform} =~ m/^(ALTERNATE)|(CAPITALISE)|(INVERT)|(RANDOM)$/sx){
        $alphabet_count += 12; # these configs guarantee a mix of cases
    }
    if($self->{_CONFIG}->{padding_digits_before} > 0 || $self->{_CONFIG}->{padding_digits_after} > 0){
        $alphabet_count += 10; # these configs guarantee digits in the mix
    }
    if($self->_passwords_will_contain_symbol()){
        $alphabet_count += 33; # the config almost certainly includes a symbol, so add 33 to the alphabet (like password haystacks does)
    }
    my $b_alphabet_count = Math::BigInt->new($alphabet_count);
    my $length_avg = round(($config_stats{length_min} + $config_stats{length_max})/2);
    $ans{permutations_blind_min} = $b_alphabet_count->copy()->bpow($b_length_min); #$alphabet_count ** $length_min;
    $_CLASS->_debug('got permutations_blind_min='.$ans{permutations_blind_min});
    $ans{permutations_blind_max} = $b_alphabet_count->copy()->bpow($b_length_max); #$alphabet_count ** $length_max;
    $_CLASS->_debug('got permutations_blind_max='.$ans{permutations_blind_max});
    $ans{permutations_blind} = $b_alphabet_count->copy()->bpow(Math::BigInt->new($length_avg)); #$alphabet_count ** $length_avg;
    $_CLASS->_debug('got permutations_blind='.$ans{permutations_blind});
    
    # calculate the seen permutations
    my $num_words = scalar @{$self->{_CACHE_DICTIONARY_LIMITED}};
    my $b_num_words = Math::BigInt->new($num_words);
    my $b_seen_perms = Math::BigInt->new('0');
    # start with the permutations from the chosen words
    if($self->{_CONFIG}->{case_transform} eq 'RANDOM'){
        # effectively doubles the numberof words in the dictionary
        $b_seen_perms->badd($b_num_words->copy()->bpow(Math::BigInt->new($self->{_CONFIG}->{num_words} * 2)));
    }else{
        $b_seen_perms->badd($b_num_words->copy()->bpow(Math::BigInt->new($self->{_CONFIG}->{num_words}))); # += $num_words ** $self->{_CONFIG}->{num_words};
    }
    # multiply in the permutations from the separator (if any - i.e. if it's randomly chosen)
    if($self->{_CONFIG}->{separator_character} eq 'RANDOM'){
        if(defined $self->{_CONFIG}->{separator_alphabet}){
            $b_seen_perms->bmul(Math::BigInt->new(scalar @{$self->{_CONFIG}->{separator_alphabet}}));
        }else{
            $b_seen_perms->bmul(Math::BigInt->new(scalar @{$self->{_CONFIG}->{symbol_alphabet}}));
        }
    }
    # multiply in the permutations from the padding character (if any - i.e. if it's randomly chosen)
    if($self->{_CONFIG}->{padding_type} ne 'NONE' && $self->{_CONFIG}->{padding_character} eq 'RANDOM'){
        $b_seen_perms->bmul(Math::BigInt->new(scalar @{$self->{_CONFIG}->{symbol_alphabet}}));
    }
    # multiply in the permutations from the padding digits (if any)
    my $num_padding_digits = $self->{_CONFIG}->{padding_digits_before} + $self->{_CONFIG}->{padding_digits_after};
    while($num_padding_digits > 0){
        $b_seen_perms->bmul(Math::BigInt->new('10'));
        $num_padding_digits--;
    }
    $ans{permutations_seen} = $b_seen_perms;
    $_CLASS->_debug('got permutations_seen='.$ans{permutations_seen});
    
    # calculate the entropy values based on the permutations
    $ans{entropy_blind_min} = $ans{permutations_blind_min}->copy()->blog(2)->numify();
    $_CLASS->_debug('got entropy_blind_min='.$ans{entropy_blind_min});
    $ans{entropy_blind_max} = $ans{permutations_blind_max}->copy()->blog(2)->numify();
    $_CLASS->_debug('got entropy_blind_max='.$ans{entropy_blind_max});
    $ans{entropy_blind} = $ans{permutations_blind}->copy()->blog(2)->numify();
    $_CLASS->_debug('got entropy_blind='.$ans{entropy_blind});
    $ans{entropy_seen} = $ans{permutations_seen}->copy()->blog(2)->numify();
    $_CLASS->_debug('got entropy_seen='.$ans{entropy_seen});
    
    # return the stats
    return %ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Calculate statistics on the loaded dictionary file
# Returns    : A hash of statistics indexed by:
#              * 'filter_length_min' - the minimum allowed word length
#              * 'filter_length_max' - the maximum allowed word length
#              * 'num_words_total' - the number of words in the un-filtered
#                dictionary file
#              * 'num_words_filtered' - the number of words after filtering on
#                size limitations
#              * 'percent_words_available' - the percentage of the un-filtered
#                words remaining in the filtered words list
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub _calcualte_dictionary_stats{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # create a hash to aggregate the stats into
    my %ans = ();
    
    # deal with agregate numbers first
    $ans{num_words_total} = scalar @{$self->{_CACHE_DICTIONARY_FULL}};
    $ans{num_words_filtered} = scalar @{$self->{_CACHE_DICTIONARY_LIMITED}};
    $ans{percent_words_available} = round(($ans{num_words_filtered}/$ans{num_words_total}) * 100);
    $ans{filter_length_min} = $self->{_CONFIG}->{word_length_min};
    $ans{filter_length_max} = $self->{_CONFIG}->{word_length_max};
    
    # return the stats
    return %ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : A function to check if passwords genereated with the loaded
#              config would contian a symbol
# Returns    : 1 if the config will produce passwords with a symbol, or 0
#              otherwise
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      : This function is used by _calculate_entropy_stats() to figure out
#              whether or not there are symbols in the alphabet when calculating
#              the brute-force entropy.
# See Also   : _calculate_entropy_stats()
sub _passwords_will_contain_symbol{
    my $self = shift;
    
    # validate args
    unless(defined $self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # assume no symbol, if we find one, set to 1
    my $symbol_used = 0;
    
    ## no critic (ProhibitEnumeratedClasses);
    # first check the padding
    if($self->{_CONFIG}->{padding_type} ne 'NONE'){
        if($self->{_CONFIG}->{padding_character} eq 'RANDOM'){
            my $all_pad_chars = join q{}, @{$self->{_CONFIG}->{symbol_alphabet}};
            if($all_pad_chars =~ m/[^0-9a-zA-Z]/sx){ # if we have just one non-word character
                $symbol_used = 1;
            }
        }else{
            if($self->{_CONFIG}->{padding_character} =~ m/[^0-9a-zA-Z]/sx){ # the padding character is not a word character
                $symbol_used = 1;
            }
        }
    }
    
    # then check the separator
    if($self->{_CONFIG}->{separator_character} ne 'NONE'){
        if($self->{_CONFIG}->{separator_character} eq 'RANDOM'){
            if(defined $self->{_CONFIG}->{separator_alphabet}){
                my $all_sep_chars = join q{}, @{$self->{_CONFIG}->{separator_alphabet}};
                if($all_sep_chars =~ m/[^0-9a-zA-Z]/sx){ # if we have just one non-word character
                    $symbol_used = 1;
                }
            }else{
                my $all_sep_chars = join q{}, @{$self->{_CONFIG}->{symbol_alphabet}};
                if($all_sep_chars =~ m/[^0-9a-zA-Z]/sx){ # if we have just one non-word character
                    $symbol_used = 1;
                }
            }
        }else{
            if($self->{_CONFIG}->{separator_character} =~ m/[^0-9a-zA-Z]/sx){ # the separator is not a word character
                $symbol_used = 1;
            }
        }
    }
    ## use critic
    
    # return
    return $symbol_used;
}

#####-SUB-######################################################################
# Type       : INSTANCE (PRIVATE)
# Purpose    : Update the entropy stats cache (and warn of low entropy if
#              appropriate)
# Returns    : always returns 1 (to keep perlcritic happy)
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      : This function should only be called from config() or dictionary().
#              The entropy is calculated with _calculate_entropy_stats(), and a
#              reference to the hash returned from that function is stored in
#              $self->{_CACHE_ENTROPYSTATS}.
# See Also   : _calculate_entropy_stats(), config() & dictionary()
sub _update_entropystats_cache{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        $_CLASS->_error('invalid invocation of instance method');
    }
    
    # do nothing if the dictionary has not been loaded yet (should only happen while the constructor is building an instance)
    return 1 unless($self->{_DICTIONARY_PATH});
    
    # calculate and store the entropy stats
    my %stats = $self->_calculate_entropy_stats();
    $self->{_CACHE_ENTROPYSTATS} = \%stats;
    
    # warn if we need to
    unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'ALL'){
        # blind warning if needed
        unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'BLIND'){
            if($self->{_CACHE_ENTROPYSTATS}->{entropy_blind_min} < $ENTROPY_MIN_BLIND){
                $_CLASS->_warn('loaded dictionary and config combination results in low minimum entropy for blind attacks ('.$self->{_CACHE_ENTROPYSTATS}->{entropy_blind_min}.", warning threshold is $ENTROPY_MIN_BLIND)");
            }
        }
        
        # seen warnings if needed
        unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'SEEN'){
            if($self->{_CACHE_ENTROPYSTATS}->{entropy_seen} < $ENTROPY_MIN_SEEN){
                $_CLASS->_warn('loaded dictionary and config combination results in low minimum entropy for attacks assuming full knowledge ('.$self->{_CACHE_ENTROPYSTATS}->{entropy_seen}.", warning threshold is $ENTROPY_MIN_SEEN)");
            }
        }
    }
    
    # to keep perl critic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : To nicely print a Math::BigInt object
# Returns    : a string representing the object's value in scientific notation
#              with 1 digit before the decimal and 2 after
# Arguments  : 1. a Math::BigInt object
# Throws     : Croaks on invalid invocation or args
# Notes      :
# See Also   :
sub _render_bigint{
    my $class = shift;
    my $bigint = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $bigint && $bigint->isa('Math::BigInt')){
        $_CLASS->_error('invalid args, must pass a Math::BigInt object');
    }
    
    # convert the bigint to an array of characters
    my @chars = split //sx, "$bigint";
    
    # render nicely
    if(scalar @chars < 3){
        return q{}.join q{}, @chars;
    }
    # start with the three most signifficant digits (as a decimal)
    my $ans = q{}.$chars[0].q{.}.$chars[1].$chars[2];
    # then add the scientific notation bit
    $ans .= 'x10^'.(scalar @chars - 1);
    
    # return the result
    return $ans;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : To try resolve a code-ref to a function name
# Returns    : A string as a scalar, or 'CODEREF' if unable to resolve
# Arguments  : 1. A coderef
# Throws     : Croaks on invalid invocation or args
# Notes      : Based on code from: http://stackoverflow.com/a/7419346
# See Also   :
sub _coderef_to_subname{
    my $class = shift;
    my $coderef = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        $_CLASS->_error('invalid invocation of class method');
    }
    unless(defined $coderef && ref $coderef eq 'CODE'){
        $_CLASS->_error('invalid arguments, must pass a code ref');
    }
    
    # try decode the reference
    my $cv = svref_2object($coderef);
    unless($cv && $cv->isa('B::CV')){
        return 'CODEREF';
    }
    my $gv = $cv->GV;
    unless($gv){
        return 'CODEREF';
    }
    
    # figure out what the ref is referring to
    my $name = '';
    if(my $st = $gv->STASH){ 
        $name = $st->NAME.'::';
    }
    my $n = $gv->NAME;
    if($n){ 
        $name .= $n;
        if($n eq '__ANON__'){ 
            $name .= ' defined at '.$gv->FILE.':'.$gv->LINE;
        }
    }
    
    # return the name
    return $name;
}

1; # because Perl is just a little bit odd :)
__END__

#==============================================================================
# User Documentation
#==============================================================================

=head1 NAME

XKPasswd - A secure memorable password generator

=head1 VERSION

This documentation refers to XKPasswd version 2.1.1.

=head1 SYNOPSIS

    use XKPasswd;

    #
    # Functional Interface - for single passwords generated from simple configs
    #
    
    # generate a single password using words from the file
    # sample_dict.txt using the default configuration
    my $password = xkpasswd('sample_dict.txt');
    
    # generate a single password using one of the module's
    # predefined presets exactly
    my $password = xkpasswd('sample_dict.txt', 'XKCD');
    
    # generate a single password using one of the module's
    # predefined presets as a starting point, but with a
    # small customisation
    my $password = xkpasswd('sample_dict.txt', 'XKCD', {separator_character => q{ }});
    
    #
    # Object Oriented Interface
    #
    
    # create a new instance with the default config
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt');
    
    # create an instance from the preset 'XKCD'
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', 'XKCD');
    
    # create an instance based on the preset 'XKCD' with one customisation
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', 'XKCD', {separator_character => q{ }});
    
    # create an instance from a config based on a preset
    # but with many alterations
    my $config = XKPasswd->preset_config('XKCD');
    $config->{separator_character} = q{ };
    $config->{case_transform} = 'INVERT';
    $config->{padding_type} = "FIXED";
    $config->{padding_characters_before} = 1;
    $config->{padding_characters_after} = 1;
    $config->{padding_character} = '*';
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', $config);
    
    # create an instance from an entirely custom configuration
    my $config = {
        symbol_alphabet => [qw{! @ $ % ^ & * + = : ~ ?}],
        separator_alphabet => [qw{- + = . _ | ~}],
        word_length_min => 6,
        word_length_max => 6,
        num_words => 3,
        separator_character => 'RANDOM',
        padding_digits_before => 2,
        padding_digits_after => 2,
        padding_type => 'FIXED',
        padding_character => 'RANDOM',
        padding_characters_before => 2,
        padding_characters_after => 2,
        case_transform => 'CAPITALISE',
        random_function => \&XKPasswd::basic_random_generator,
        random_increment => 'AUTO',
        character_substitutions => {}
    }
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', $config);
    
    # generate a single password
    my $password = $xkpasswd_instance->password();
    
    # generate multiple passwords
    my @passwords = $xkpasswd_instance->passwords(10);

=head1 DESCRIPTION

A secure memorable password generator inspired by the wonderful XKCD webcomic
at L<http://www.xkcd.com/> and Steve Gibson's Password Haystacks page at
L<https://www.grc.com/haystack.htm>. This is the Perl library that powers
L<https://www.xkpasswd.net>.

=head2 PHILOSOPHY

More and more of the things we do on our computer require passwords, and at the
same time it seems we hear about organisations or sites losing user database on
every day that ends in a I<y>. If we re-use our passwords we expose ourself to
an ever greater risk, but we need more passwords than we can possibly remember
or invent. Coming up with one good password is easy, but coming up with one
good password a week is a lot harder, let alone one a day!

Obviously we need some technological help. We need our computers to help us
generate robust password and store them securely. There are many great password
managers out there to help us securely store and sync our passwords, including
commercial offerings and open-source projects. Many of these managers also offer
to generate random passwords for us, usually in the form of a random string of
meaningless letters numbers and symbols. These kinds of nonsense passwords are
certainly secure, but they are often impractical.

Regardless of how good your chosen password manager is, there will always be
times when you need to type in your passwords, and that's when random gibberish
passwords become a real pain point. As annoying as it is to have to glance over
and back at a small cellphone screen to manually type a gibberish password into
a computer, that's nothing compared to the annoyance of trying to communicate
such a password to a family member, friend, colleague or customer over the phone.

Surely it would be better to have passwords that are still truly random in the
way humans can't be, but are also human-friendly in the way random gibberish
never will be? This is the problem this module aims to solve.

Rather than randomly choosing many letters, digits, and symbols from a fairly
small alphabet of possible characters, this library chooses a small number of
words from a large I<alphabet> of possible words as the basis for passwords.
Words are easy to remember, easy to read from a screen, easy to type, and easy
to communicate over the telephone.

This module uses words to make up the bulk of the passwords it generates, but
it also adds carefully placed random symbols and digits to add more security
without the passwords difficult to remember, read, type, or speak.

In shot, this module is for people who prefer passwords that look like this:

    !15.play.MAJOR.fresh.FLAT.23!

to passwords that look like this:

    eB8.GJXa@TuM

=head2 THE MATHS

Before examining the password strength of passwords generated with this module
we need to lay out the relatively simple maths underlying it all.

=head3 Maths Primer

A coin could be used as a very simple password generator. Each character in
the password would be the result of a single coin toss. If the coin lands
heads up, we add a C<H> to our password, if it lands tails up, we add a C<T>.

If you made a one-letter password in this way there would only be two
possibilities, C<H>, or C<T>, or two permutations. If you made a two-letter
password in this way there would be four possible combinations, or
permutations, C<HH>, C<HT>, C<TH>, and C<TT>. If you made a three-character
password in this way there would be 16 permutations, a five character one
would have 32 permutations, and so forth.

So, for a coin toss, which has two possible values for each character, the
formula for the number of permutations C<P> for a given length of password C<L>
is:

    P = 2^L

Or, two to the power of the length of the password.

If we now swapped our coin for a dice, we would go from two possible values
per letter, to six possible values per letter. For one dice roll there would
be six permutations, for two there would be 36, for three there would be 108
and so on.

This means that for a dice, the number of permutations can be calculated with
the formula:

    P = 6^L

When talking about passwords, the set of possible symbols used for each
character in the password is referred to as the password's I<alphabet>. So,
for the coin toss the alphabet was just C<H> and C<T>, and for the dice it
was C<1>, C<2>, C<3>, C<4>, C<5>, and C<6>. The actual characters used in
the alphabet make no difference to the strength of the password, all that
matters is the size of the alphabet, which we'll call C<A>.

As you can probably infer from the two examples above, the formula for the
number of possible permutations C<P> for a password of length C<L> created from
an alphabet of size C<A> is:

    P = A^L

In the real world our passwords are generally made up of a mix of letters,
digits, and symbols. If we use mixed case that gives us 52 letters alone,
then add in the ten digits from C<0> to C<9> and we're already up to 62
possible characters before we even start on the array of symbols and
punctuation characters on our keyboards. It's generally accepted that if you
include symbols and punctuation, there are 95 characters available for use in
randomly generated passwords. Hence, in the real-world, the value for C<A> is
assumed to be 95. When you start raising a number as big as 95 to even low
powers the number of permutations quickly rises.

A two character password with alphabet of 95 has 9025 permutations, increasing
the length to three characters brings that up to 857,375, and so on. These
numbers very quickly become too big to handle. For just an 8 character password
we are talking about 6,634,204,312,890,625 permutations, which is a number
so big most people couldn't say it (what do you call something a thousand times
bigger than a trillion?).

Because the numbers get so astronomically big so quickly, computer scientists
use bits of entropy to measure password strength rather than the number of
permutations. The formula to turn permutations into bits of entropy C<E> is very
simple:

    E = Log(2)P

In other words, the entropy is the log to base two of the permutations. For our
eight character example that equates to about 52 bits.

There are two approaches to increasing the number of permutations, and hence
the entropy, you can choose more characters, or, you can make the alphabet you
are choosing from bigger.

=head3 The Entropy of XKPasswd Passwords

Exactly how much entropy does a password need? That's the subject of much
debate, and the answer ultimately depends on the value of the assets being
protected by the password.

Two common recommendations you hear are 8 characters containing a mix of upper
and lower case letters, digits, and symbols, or 12 characters with the same
composition. These evaluation to approximately 52 bits of entropy and 78 bits
of entropy respectively.

When evaluating the entropy of passwords generated by this module, it has to be
done from two points of view for the answer to be meaningful. Firstly, a
best-case scenario - the attacker has absolutely no knowledge of how the
password was generated, and hence must mount a brute-force attack. Then,
secondly from the point of view of an attacker with full knowledge of how the
password was generated. Not just the knowledge that this module was used, but
a copy of the dictionary file used, and, a copy of the configuration settings
used.

For the purpose of this documentation, the entropy in the first scenario, the
brute force attack, will be referred to as the blind entropy, and the entropy
in the second scenario the seen entropy.

The blind entropy is solely determined by the configuration settings, the seen
entropy depends on both the settings and the dictionary file used.

Calculating the bind entropy C<Eb> is quite straightforward, we just need to
know the size of the alphabet resulting from the configuration C<A>, and the
minimum length of passwords generated with the configuration C<L>, and plug
those values into this formula:

    Eb = Log(2)(A^L)

Calculating C<A> simply involves determining whether or not the configuration
results in a mix of letter cases (26 or 52 characters), the inclusion of at
least one symbol (if any one is present, assume the industry standard of a 33
character search space), and the inclusion of at least one digit
(10 character). This will result in a value between 26 and 95.

Calculating C<L> is also straightforward. The one minor complication is that
some configurations result in a variable length password. In this case,
assume the shortest possible length the configuration could produce.

The example password from the L</PHILOSOPHY> section
(C<!15.play.MAJOR.fresh.FLAT.23!>) was generated using the preset C<WEB32>.
This preset uses four words of between four and five letters long, with the
case of each word randomly set to all lower or all upper as the
basis for the password, it then chooses two pairs of random digits as extra
words to go front and back, before separating each word with a copy of a
randomly chosen symbol, and padding the front and back of the password with
a copy of a different randomly chosen symbol. This results in passwords that
contain a mix of cases, digits, and symbols, and are between 27 and 31
characters long. If we add these values into the formula we find that the
blind entropy for passwords created with this preset is:

    Eb = Log(2)(95^27) = 163 bits

This is spectacularly secure! And, this is the most likely kind of attack for
a password to face. However, to have confidence in the password we must also
now calculate the entropy when the attacker knows everything about how the
password was generated.

We will calculate the entropy resulting from the same C<WEB32> config being
used to generate a password using the sample library file that ships with
the module.

The number of permutations the attacker needs to check is purely the product
of possibly results for each random choice made during the assembly of the
password.

Lets start with the words that will form the core of the password. The
configuration chooses four words of between four and five letters long from
the dictionary, and then randomises their case, effectively making it a
choice from twice as many words (each word in each case).

The sample dictionary file contains 698 words of the configured length, which
doubles to 1396. Choosing four words from that very large alphabet gives a
starting point of C<1396^4>, or 3,797,883,801,856 permutations.

Next we need to calculate the permutations for the separator character. The
configuration specifies just nine permitted characters, and we choose just one,
so that equates to 9 permutations.

Similarly, the padding character on the end is chosen from 13 permitted symbols
giving 13 more permutations.

Finally, there are four randomly chosen digits, giving C<10^4>, or 10,000
permutations.

The total number of permutations is the product of all these permutations:

    Pseen = 3,797,883,801,856 * 9 * 13 * 10,000 = 2.77x10^17
    
Finally, we convery this to entropy by taking the base 2 log:

    Eseen = Log(2)2.77x10^17 = ~57bits
    
What this means is that most probably, passwords generated with this preset
using the sample dictionary file are spectacularly more secure than even
12 randomly chosen characters, and, that in the very unlikely event that an
attackers knows absolutely everything about how the password was generated,
it is still significantly more secure than 8 randomly chosen characters.

Because the exact strength of the passwords produced by this module depend on
the configuration and dictionary file used, the constructor does the above
math when creating an XKPasswd object, and throws a warning if either the
blind entropy falls below 78bits, or the seen entropy falls below 52 bits.

=head1 SUBROUTINES/METHODS

=head2 DICTIONARY FILES

XKPasswd instances load their word lists from text files. The constructor
loads the words contained in a single file into memory when assembling an
XKPasswd object. Once constructed, the object never reads from the file again.
Throughout this documentation, the text file containing the words to be used is
referred to as I<the Dictionary File>, and specified via the
C<dictionary_file_path> config variable.

The rules for the formatting of dictionary files are simple. Dictionary
files must contain one word per line. Words shorter than four letters will be
ignored, as will all lines starting with the # symbol.

This format is the same as that of the standard Unix Words file, usually found
at C</usr/share/dict/words> on Unix and Linux operating systems (including OS
X).

In order to produce secure passwords it's important to use a dictionary file
that contains a large selection of words with a good mix of different word
lengths.

A sample dictionary file (C<sample_dict.txt>) is distributed with this
module.

=head2 CONFIGURATION HASHREFS

A number of subroutines require a configuration hashref as an argument. The
following are the valid keys for that hashref, what they mean, and what values
are valid for each.

=over 4

=item *

C<case_transform> - the alterations that should be made to the case of the
letters in the randomly chosen words that make up the bulk of the randomly
generated passwords. Must be a scalar, and the only valid values for this key
are:

=over 4

=item -

C<ALTERNATE> - each alternate word will be converted to all upper case and
all lower case.

=item -

C<CAPITALISE> - the first letter in every word will be converted to upper case,
all other letters will be converted to lower case.

=item -

C<INVERT> - the first letter in every word will be converted to lower case,
all other letters will be converted to upper case.

=item -

C<LOWER> - all letters in all the words will be converted to lower case. B<Use
of this option is strongly discouraged for security reasons.>

=item -

C<NONE> - the capitalisation used in the randomly generated password will be
the same as it is in the dictionary file.

=item -

C<RANDOM> - each word will be randomly converted to all upper case or all lower
case.

=item -

C<UPPER> - all letters in all the words will be converted to upper case. B<Use
of this option is strongly discouraged for security reasons.>

=back

The default value returned by C<default_config()> is C<CAPITALISE>.

=item *

C<character_substitutions> - a hashref containing zero or more character
substitutions to be applied to the words that make up the bulk of the generated
passwords. The keys in the hashref are the characters to be replaced, and must
be single alpha numeric characters, while the values in the hashrefs are the
replacements, and can be longer.

=item *

C<num_words> - the number of randomly chosen words use as the basis for the
generated passwords. The default value is four. For security reasons, at least
two words must be used.

=item *

C<pad_to_length> - the total desired length of the password when using adaptive
padding (C<padding_type> set to C<ADAPTIVE>). Must be a scalar with an integer
values greater than or equal to 12 (for security reasons).

=item *

C<padding_character> - the character to use when padding the front and/or back
of the randomly generated password. Must be a scalar containing either a single
character or one of the special values C<RANDOM> (indicating that a character
should be chosen at random from the C<symbol_alphabet>), or C<SEPARATOR> (use
the same character used to separate the words). This key is only needed if
C<padding_type> is set to C<FIXED> or C<ADAPTIVE>. The default value returned
by C<default_config> is C<RANDOM>.

=item *

C<padding_characters_before> & C<padding_characters_after> - the number of
symbols to pad the front and end of the randomly generated password with. Must
be a scalar with an integer value greater than or equal to zero. These keys are
only needed if C<padding_type> is set to C<FIXED>. The default value returned
by C<default_config()> for both these keys is 2.

=item *

C<padding_digits_before> & C<padding_digits_after> - the number of random
digits to include before and after the randomly chosen words making up the bulk
of the randomly generated password. Must be scalars containing integer values
greater than or equal to zero. The default value returned by
C<default_config()> for both these keys is 2. 

=item *

C<padding_type> - the type of symbol padding to be added at the start and/or
end of the randomly generated password. Must be a scalar with one of the
following values:

=over 4

=item -

C<NONE> - do not pad the generated password with any symbol characters.

=item -

C<FIXED> - a specified number of symbols will be added to the front and/or
back of the randomly generated password. If this option is chosen, you must
also specify the keys C<padding_character>, C<padding_characters_before> &
C<padding_characters_after>.

=item -

C<ADAPTIVE> - no symbols will be added to the start of the randomly generated
password, and the appropriate number of symbols will be added to the end to
make the generated password exactly a certain length. The desired length is
specified with the key C<pad_to_length>, which is required if this padding type
is specified.

=back

The default value returned by C<default_config()> is C<FIXED>.

=item *

C<random_function> - a reference to the function to be used use to generate
random numbers during the password generation process. The function generate
an array of random decimal numbers between 0 and 1, take one argument, the
number of random numbers to generate, and it must return an array. By default
the function C<XKPasswd::basic_random_generator()> is used.

=item *

C<random_increment> - the number of random digits to generate at a time when
ever the instance's cache of randomness runs low. Must be an integer greater
than or equal to 1, or the special value C<AUTO>. When the value is set to
C<AUTO> a call to C<config_stats()> is used to determine the amount of random
numbers needed to generate a single password, and this value is used as the
random increment. The default value is c<AUTO>.

=item *

C<separator_alphabet> - this key is optional. It can be used to override
the contents of C<symbol_alphabet> when C<separator_character> is set to
C<RANDOM>. If present this key must contain an arrayref containing at
least two single characters as scalars.

=item *

C<separator_character> - the character to use to separate the words in the
generated password. Must be a scalar, and acceptable values are a single
character, or, the special values C<NONE> (indicating that no separator should
be used), or C<RANDOM>, indicating that a character should be chosen at random
from the C<symbol_alphabet>. The default value returned by C<default_config()>
is C<RANDOM>.

=item *

C<symbol_alphabet> - an arrayref containing at least two single characters as
scalars. This alphabet will be used when selecting random characters to act as
the separator between words, or the padding at the start and/or end of
generated passwords. The default value returned by C<default_config()> is
C<[qw{! @ $ % ^ & * - _ + = : | ~ ?}]>

=item *

C<word_length_min> & C<word_length_max> - the minimum and maximum length of the
words that will make up the generated password. The two keys must be scalars,
and can hold equal values, but C<word_length_max> may not be smaller than
C<word_length_min>. For security reasons, both values must be greater than 3.
The default values returned by C<default_config()> is are 4 & 8.

=back

=head2 PRESETS

For ease of use, this module comes with a set of pre-defined presets. Preset
names can be used in place of config hashrefs when instantiating an XKPasswd
object, or, when using the functional interface to XKPasswd.

Presets can be used as-is, or, they can be used as a starting point for
creating your own config hashref, as demonstrated by the following example:

    my $config = XKPasswd->preset_config('XKCD');
    $config->{separator_character} = q{ }; # change the separator to a space
    my $xkpasswd = XKPasswd->new('sample_dict.txt', $config);
    
If you only wish to alter a small number of config settings, the following
two shortcuts might be of interest (both produce the same result as the
example above):

    my $config = XKPasswd->preset_config('XKCD', {separator_character => q{ }});
    my $xkpasswd = XKPasswd->new('sample_dict.txt', $config);
    
or

    my $xkpasswd = XKPasswd->new('sample_dict.txt', 'XKCD', {separator_character => q{ }});

For more see the definitions for the class functions C<defined_presets()>,
C<presets_to_string()>, and C<preset_config()>.

The following presets are defined:

=over 4

=item *

C<APPLEID> - a preset respecting the many prerequisites Apple places on Apple
ID passwords. Apple's official password policy is located here:
L<http://support.apple.com/kb/ht4232>. Note that Apple's knowledge base article
omits to mention that passwords can't be longer than 32 characters. This preset
is also configured to use only characters that are easy to type on the standard
iOS keyboard, i.e. those appearing on the letters keyboard (C<ABC>) or the
numbers keyboard C<.?123>, and not those on the harder to reach symbols
keyboard C<#+=>. Below is a sample password generated with this preset:

    @60:london:TAUGHT:forget:70@

=item *

C<DEFAULT> - the default configuration. Below is a sample password generated
with this preset:

    ~~12:Settle:Whether:Succeed:Summer:48~~

=item *

C<NTLM> - a preset for 14 character NTMLv1 (NTLM Version 1) passwords. ONLY USE
THIS PRESET IF YOU MUST! The 14 character limit does not allow for sufficient
entropy in the case where the attacker knows the dictionary and config used
to generate the password, hence this preset will generate low entropy warnings.
Below is a sample password generated with this preset:

    0=mAYAN=sCART@

=item *

C<SECURITYQ> - a preset for creating fake answers to security questions. It
generates long nonsense sentences ending in C<.> C<!> or C<?>, for example:

    Wales outside full month minutes gentle?

=item *

C<WEB16> - a preset for websites that don't allow more than 16 character long
passwords. Because 16 characters is not very long, a large set of
symbols are chosen from for the padding and separator. Below is a sample
password generated with this preset:

    :baby.ohio.DEAR:
    
=item *

C<WEB32> - a preset for websites that don't allow more than 32 character long
passwords. Below is a sample password generated with this preset:

    +93-took-CASE-money-AHEAD-31+

=item *

C<WIFI> - a preset for generating 63 character long WPA2 keys (most routers
allow 64 characters, but some only 63, hence the odd length). Below is a sample
password generated with this preset:

    2736_ITSELF_PARTIAL_QUICKLY_SCOTLAND_wild_people_7441!!!!!!!!!!

=item *

C<XKCD> - a preset inspired by the original XKCD comic
(L<http://xkcd.com/936/>), but with some alterations to provide sufficient
entropy to avoid low entropy warnings. Below is a sample password generated
with this preset:

    KING-madrid-exercise-BELGIUM

=back

=head2 ENTROPY CHECKING

For security reasons, this module's default behaviour is to warn (using
C<carp()>) when ever the loaded combination dictionary file and configuration
would result in low-entropy passwords. When the constructor is invoked, or when
a new dictionary file or new config hashref are loaded into an object (using
C<dictionary()> or C<config()>) the entropy of the resulting new state of the
object is calculated and checked against the defined minima.

Entropy is calculated and checked for two scenarios. Firstly, for the best-case
scenario, when an attacker has no prior knowledge about the password, and must
resort to brute-force attacks. And secondly, for the worst-case scenario, when
the attacker is assumed to know that this module was used to generate the
password, and, that the attacker has a copy of the dictionary file and config
settings used to generate the password.

Entropy checking is controlled via three package variables:

=over 4

=item *

C<$XKPasswd::ENTROPY_MIN_BLIND> - the minimum acceptable entropy (in bits) for
a brute-force attack. The default value for this variable is 78 (equivalent to
a 12 character password consisting of mixed-case letters, digits, and symbols).

=item *

C<$XKPasswd::ENTROPY_MIN_SEEN> - the minimum acceptable entropy (in bits) for a
worst-case attack (where the dictionary and configuration are known). The default
value for this variable is 52 (equivalent to an 8 character password consisting
of mixed-case letters, digits, and symbols).

=item *

C<$XKPasswd::SUPRESS_ENTROPY_WARNINGS> - this variable can be used to suppress
one or both of the entropy warnings. The following values are valid (invalid
values are treated as being C<NONE>):

=over 4

=item -

C<NONE> - no warnings are suppressed. This is the default value.

=item -

C<SEEN> - only warnings for the worst-case scenario are suppressed.

=item -

C<BLIND> - only warnings for the best-case scenario are suppressed.

=back

=back

=head3 CAVEATS

The entropy calculations make some assumptions which may in some cases lead to
the results being inaccurate. In general, an attempt has been made to always
round down, meaning that in reality the entropy of the produced passwords may
be higher than the values calculated by the package.

When calculating the entropy for brute force attacks on configurations that can
result in variable length passwords, the shortest possible password is assumed.

When calculating the entropy for brute force attacks on configurations that
contain at least one symbol, it is assumed that an attacker would have to
brute-force-check 33 symbols. This is the same value used by Steve Gibson's
I<Password Haystacks> calculator (L<https://www.grc.com/haystack.htm>).

When calculating the entropy for worst-case attacks on configurations that
contain symbol substitutions where the replacement is more than 1 character
long the possible extra length is ignored.

=head2 RANDOM FUNCTIONS

In order to avoid this module relying on any non-standard modules, the default
source of randomness is Perl's built-in C<rand()> function. This provides a
reasonable level of randomness, and should suffice for most users, however,
some users will prefer to make use of one of the many advanced randomisation
modules in CPAN, or, reach out to a web service like L<http://random.org> for
their randomness. To facilitate both of these options, this module uses a
cache of randomness, and allows a custom randomness function to be specified
by setting the config variable C<random_function> to a coderef to the function.

Functions specified in this way must take exactly one argument, an integer
number greater than zero, and then return that many random decimal numbers
between zero and one.

The random function is not called each time a random number is needed, instead
a number of random numbers are generated at once, and cached until they are
needed. The amount of random numbers generated at once is controlled by the
C<random_increment> config variable. The reason the module works in this way
is to facilitate web-based services which prefer you to generate many numbers
at once rather than invoking them repeatedly. For example, Random.org ask
developers to query them for more random numbers less frequently.

=head2 FUNCTIONAL INTERFACE

Although the package was primarily designed to be used in an object-oriented
way, there is a functional interface too. The functional interface initialises
an object internally and then uses that object to generate a single password.
If you only need one password, this is no less efficient than the
object-oriented interface, however, if you are generating multiple passwords it
is much less efficient.

There is only a single function exported by the module:

=head3 xkpasswd()

    my $password = xkpasswd('sample_dict.txt');
    
This function call is equivalent to the following Object-Oriented code:

    my $xkpasswd = XKPasswd->new('sample_dict.txt');
    my $password = $xkpasswd->password();
    
This function passes its arguments through to the constructor, so all arguments
that are valid in C<new()> are valid here.

This function Croaks if there is a problem generating the password.

Note that it is inefficient to use this function to generate multiple passwords
because the dictionary file will be re-loaded, and the entropy
calculations for ensuring security repeated, each time a password is generated.


=head2 CONSTRUCTOR
    
    # create a new instance with the default config
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt');
    
    # create an instance from the preset 'XKCD'
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', 'XKCD');
    
    # create an instance based on the preset 'XKCD' with one customisation
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', 'XKCD', {separator_character => q{ }});
    
    # create an instance from a config hashref
    my $xkpasswd_instance = XKPasswd->new('sample_dict.txt', $config_hashref);

The constructor must be called via the package name, and at least one argument
must be passed, the path to the dictionary file to be used when generating the
words.

If only one argument is passed the default values are used for all config keys.
To use a different configuration, a second argument can be passed. If this
argument is a scalar it will be assumed to be the name of a preset, and if it
is a hashref it is assumed to be the config to load.

If a preset name is passed as a second argument, a hashref with config key
overrides can be passed as a third argument. If the second argument is a hashref
the third argument is ignored.

=head2 CLASS METHODS

B<NOTE> - All class methods must be invoked via the package name, or they will
croak.

=head3 clone_config()

    my $clone = XKPasswd->clone_config($config);
    
This function must be passed a valid config hashref as the first argument or it
will croak. The function returns a hashref.

=head3 config_stats()

    my %stats = XKPasswd->config_stats($config);
    
This function requires one argument, a valid config hashref. It returns a hash
of statistics about a given configuration. The hash is indexed by the
following:

=over 4

=item *

C<length_min> - the minimum length a password generated with the given
config could be.

=item *

C<length_max> - the maximum length a password generated with the given
config could be. (see caveat below)

=item *

C<random_numbers_required> - the amount of random numbers needed to generate a
password using the given config.

=back

There is one scenario in which the calculated maximum length will not be
reliably accurate, and that's when a character substitution with a length
greater than 1 is specified, and C<padding_type> is not set to C<ADAPTIVE>. If
the config passed contains such a character substitution, the length will be
calculated ignoring the possibility that one or more extra characters could
be introduced depending on how many, if any, of the long substitutions get
triggered by the randomly chosen words. If this happens the function will also
carp with a warning.

=head3 config_to_string()

    my $config_string = XKPasswd->config_to_string($config);
    
This function returns the content of the passed config hashref as a scalar
string. The function must be passed a valid config hashref or it will croak.

=head3 default_config()

    my $config = XKPasswd->default_config();

This function returns a hashref containing a config with default values.

This function can optionally be called with a single argument, a hashref
containing keys with values to override the defaults with.

    my $config = XKPasswd->default_config({num_words => 3});
    
When overrides are present, the function will carp if an invalid key or value
is passed, and croak if the resulting merged config is invalid.

This function is a shortcut for C<preset_config()>, and the two examples above
are equivalent to the following:

    my $config = XKPasswd->preset_config('DEFAULT');
    my $config = XKPasswd->preset_config('DEFAULT', {num_words => 3});

=head3 defined_presets()

    my @preset_names = XKPasswd->defined_presets();
    
This function returns the list of defined preset names as an array of scalars.

=head3 is_valid_config()

    my $is_ok = XKPasswd->is_valid_config($config);
    
This function must be passed a hashref to test as the first argument or it will
croak. The function returns 1 if the passed config is valid, and 0 otherwise.

Optionally, any truthy value can be passed as a second argument to indicate
that the function should croak on invalid configs rather than returning 0;

    use English qw( -no_match_vars );
    eval{
        XKPasswd->is_valid_config($config, 'do_croak');
    }or do{
        print "ERROR - config is invalid because: $EVAL_ERROR\n";
    }

=head3 preset_config()

    my $config = XKPasswd->preset_config('XKCD');
    
This function returns the config hashref for a given preset. See above for the
list of available presets.

The first argument this function accpets is the name of the desired preset as a
scalar. If an invalid name is passed, the function will carp. If no preset is
passed the preset C<DEFAULT> is assumed.

This function can optionally accept a second argument, a hashref
containing keys with values to override the defaults with.

    my $config = XKPasswd->preset_config('XKCD', {case_transform => 'INVERT'});
    
When overrides are present, the function will carp if an invalid key or value is
passed, and croak if the resulting merged config is invalid.

=head3 presets_to_string()

    print XKPasswd->presets_to_string();
    
This function returns a string containing a description of each defined preset
and the configs associated with the presets.

=head2 METHODS

B<NOTE> - all methods must be invoked on an XKPasswd object or they will croak.

=head3 config()

    my $config = $xkpasswd_instance->config(); # getter
    $xkpasswd_instance->config($config); # setter

When called with no arguments the function returns a clone of the instance's
config hashref.

When called with a single argument the function sets the config of the instance
to a clone of the passed hashref. If present, the argument must be a hashref,
and must contain valid config keys and values. The function will croak if an
invalid config is passed.

=head3 config_string()

    my $config_string = $xkpasswd_instance->config_string();
    
This function returns the content of the passed config hashref as a scalar
string. The function must be passed a valid config hashref or it will croak.

=head3 dictionary()

    print $xkpasswd_instance->dictionary();
    $xkpasswd_instance->dictionary('sample_dict.txt');
    
When called with no arguments this function returns the path to the currently
loaded dictionary file. To load a dictionary file into an instance call this
function with the path to the dictionary file.

=head3 password()

    my $password = $xkpasswd_instance->password();
    
This function generates a random password based on the instance's loaded config
and returns it as a scalar. The function takes no arguments.

The function croaks if there is an error generating the password. The most
likely cause of and error is the random number generation, particularly if the
loaded random generation function relies on a cloud service or a non-standard
library.

=head3 passwords()

    my @passwords = $xkpasswd_instance->passwords(10);
    
This function generates a number of passwords and returns them all as an array.

The function uses C<password()> to genereate the passwords, and hence will
croak if there is an error generating any of the requested passwords.

=head3 stats()

    my %stats = $xkpasswd_instance->stats();
    
This function generates a hash containing stats about the instance indexed by
the following keys:

=over 4

=item *

C<dictionary_filter_length_min> & C<dictionary_filter_length_max> - the minimum
and maximum word lengths allowed by the dictionary filter (defined by config
keys C<word_length_min> and C<word_length_max>)

=item *

C<dictionary_path> - the path to the dictionary file loaded into the instance.

=item *

C<dictionary_words_filtered> - the number of words loaded from the dictionary
file that meet the criteria defined by the loaded config.

=item *

C<dictionary_words_percent_avaialable> - the percentage of the words in the
dictionary file that are available for use with the loaded config.

=item *

C<dictionary_words_total> - the total number of words loaded from the
dictionary file.

=item *

C<password_entropy_blind_min> - the entropy (in bits) of the shortest password
the loaded config can generate from the point of view of a brute-force
attacker.

=item *

C<password_entropy_blind_max> - the entropy (in bits) of the longest password
the loaded config can generate from the point of view of a brute-force
attacker.

=item *

C<password_entropy_blind> - the entropy (in bits) of the average length
of passwords the loaded config can generate from the point of view of a
brute-force attacker.

=item *

C<password_entropy_seen> - the  entropy (in bits) of passwords generated by the
instance assuming the dictionary and config are known to the attacker.

=item *

C<password_length_min> - the minimum length of passwords generated by the
loaded config.

=item *

C<password_length_max> - the maximum length of passwords generated by the
loaded config.

=item *

C<password_permutations_blind_min> - the number of permutations a brute-force
attacker would have to try to be sure of cracking the shortest possible
passwords generated by this instance. Because this number can be very big, it's
returned as a C<Math::BigInt> object.

=item *

C<password_permutations_blind_max> - the number of permutations a brute-force
attacker would have to try to be sure of cracking the longest possible
passwords generated by this instance. Because this number can be very big, it's
returned as a C<Math::BigInt> object.

=item *

C<password_permutations_blind> - the number of permutations a brute-force
attacker would have to try to be sure of cracking an average length password
generated by this instance. Because this number can be very big, it's returned
as a C<Math::BigInt> object.

=item *

C<password_permutations_seen> - the number of permutations an attacker with a
copy of the dictionary and config would need to try to be sure of cracking a
password generated by this instance. Because this number can be very big, it's
returned as a C<Math::BigInt> object.

=item *

C<passwords_generated> - the number of passwords this instance has generated.

=item *

C<password_random_numbers_required> - the number of random numbers needed to
generate a single password using the loaded config.

=item *

C<randomnumbers_cached> - the number of random numbers currently cached within
the instance.

=item *

C<randomnumbers_cache_increment> - the number of random numbers generated at
once to replenish the cache when it's empty.

=item *

C<randomnumbers_generator_function> - the function used by the instance to
generate random numbers.

=back

=head3 status()

    print $xkpasswd_instance->status();
    
Generates a string detailing the internal status of the instance. Below is a
sample status string:

    *DICTIONARY*
    File path: /usr/share/dict/words
    # words: 234252
    # words of valid length: 87066

    *CONFIG*
    case_transform: 'CAPITALISE'
    character_substitutions: {}
    num_words: '4'
    padding_digits_after: '0'
    padding_digits_before: '0'
    padding_type: 'NONE'
    random_function: XKPasswd::basic_random_generator
    random_increment: '4'
    separator_character: '-'
    word_length_max: '8'
    word_length_min: '4'

    *RANDOM NUMBER CACHE*
    # in cache: 0

    *PASSWORD STATISTICS*
    Password length: between 19 & 35
    Brute-Force permutations: between 2.29x10^33 & 2.85x10^61 (average 2.56x10^47)
    Permutations (given dictionary & config): 5.74x10^19
    Brute-Force Entropy (in bits): between 110 and 204 (average 157)
    Entropy (given dictionary & config): 65bits
    Passwords Generated: 0

=head3 update_config()

    $xkpasswd_instance->update_config({separator_character => '+'});
    
The function updates the config within an XKPasswd instance. A hashref with the
config options to be changed must be passed. The function returns a reference to
the instance to enable function chaining. The function will croak if the updated
config would be invalid in some way. Note that if this happens the running
config will not have been altered in any way.

=head1 DIAGNOSTICS

By default this module does all of it's error notification via the functions
C<carp()>, C<croak()>, and C<confess()> from the C<Carp> module. Optionally,
all error messages can also be printed. To enable the printing of messages,
set C<$XKPasswd::LOG_ERRORS> to a truthy value. All error messages will then be
printed to the stream at C<$XKPasswd::LOG_STREAM>, which is set to C<STDERR> by
default.

Ordinarily this module produces very little output, to enable more verbose
output C<$XKPasswd::DEBUG> can be set to a truthy value. If this is set, all
debug messages will be printed to the stream C<$XKPasswd::LOG_STREAM>.

This module produces output at three severity levels:

=over 4

=item *

C<DEBUG> - this output is completely suppressed unless C<$XKPasswd::DEBUG> is
set to a truthy value. If not suppressed debug messages are always printed to
C<$XKPasswd::LOG_STREAM> (regardless of the value of C<$XKPasswd::LOG_ERRORS>).

=item *

C<WARNING> - warning messages are always thrown with C<carp()>, and also
printed to C<$XKPasswd::LOG_STREAM> if C<$XKPasswd::LOG_ERRORS> evaluates to
true.

=item *

C<ERROR> - error messages are usually thrown with C<croak()>, but will be
thrown with C<confess()> if C<$XKPasswd::DEBUG> evaluates to true. If
C<$XKPasswd::LOG_ERRORS> evaluates to true errors are also printed to
C<$XKPasswd::LOG_STREAM>, including a stack trace if C<$XKPasswd::DEBUG>
evaluates to true and the module C<Devel::StackTrace> is installed.


=back

=head1 CONFIGURATION AND ENVIRONMENT

This module does not currently support configuration files, nor does it
currently interact with the environment. It may do so in future versions.

=head1 DEPENDENCIES

This module uses the following standard Perl modules:

=over 4

=item *

C<strict> - L<http://search.cpan.org/perldoc?strict>

=item *

C<warnings> - L<http://search.cpan.org/perldoc?warnings>
=item *

C<Carp> - L<http://search.cpan.org/perldoc?Carp>

=item *

C<English> - L<http://search.cpan.org/perldoc?English>

=item *

C<B> - L<http://search.cpan.org/perldoc?B>

=item *

C<Math::Round> - L<http://search.cpan.org/perldoc?Math%3A%3ARound>

=item *

C<Math::BigInt> - L<http://search.cpan.org/perldoc?Math%3A%3ABigInt>

=back

The module can also optionally use the following non-standard Perl modules:

=over 4

=item *

C<Devel::StackTrace> - L<http://search.cpan.org/perldoc?Devel%3A%3AStackTrace>

Used for printing stack traces with error messages if
C<$XKPasswd::DEBUG> and C<$XKPasswd::LOG_ERRORS> both evaluate to true. If the
module is not installed the stack traces will be omitted from the log messages.

=back

=head1 INCOMPATIBILITIES

This module has no known incompatibilities.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.

Please report problems to Bart Busschots (L<mailto:bart@bartificer.net>) Patches are welcome.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2014, Bart Busschots T/A Bartificer Web Solutions
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

=over 4

=item 1.

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer. 

=item 2.

Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

=back

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=head1 AUTHOR

Bart Busschots (L<mailto:bart@bartificer.net>)