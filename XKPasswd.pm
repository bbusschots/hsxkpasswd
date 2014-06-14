package XKPasswd;

use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code

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
my $MIN_WORDS = 100;

# utility variables
my $_CLASS = 'XKPasswd';

# config key definitions
my $_KEYS = {
    symbol_alphabet => {
        req => 1,
        ref => 'ARRAY', # ARRAY REF
        validate => sub { # at least 5 scalar elements
            my $key = shift;
            unless(scalar @{$key} >= 5){ return 0; }
            foreach my $symbol (@{$key}){
                unless(ref $symbol eq q{} && $symbol =~ m/^.$/sx){ return 0; }
            }
            return 1;
        },
        desc => 'An array ref containing at least 5 single-character scalars',
    },
    separator_alphabet => {
        req => 0,
        ref => 'ARRAY', # ARRAY REF
        validate => sub { # at least 3 scalar elements
            my $key = shift;
            unless(scalar @{$key} >= 3){ return 0; }
            foreach my $symbol (@{$key}){
                unless(ref $symbol eq q{} && $symbol =~ m/^.$/sx){ return 0; }
            }
            return 1;
        },
        desc => 'An array ref containing at least 3 single-character scalars',
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
            unless($key =~ m/^[.]|(NONE)|(RANDOM)$/sx){ return 0; }
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
        validate => sub { # positive integer
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 1){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to one',
    },
    padding_characters_after => {
        req => 0,
        ref => q{}, # SCALAR
        validate => sub { # positive integer
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 1){ return 0; }
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
            unless($key =~ m/^[.]|(NONE)|(RANDOM)|(SEPARATOR)$/sx){return 0; }
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
        validate => sub { # positive integer >= 1
            my $key = shift;
            unless($key =~ m/^\d+$/sx && $key >= 1){ return 0; }
            return 1;
        },
        desc => 'A scalar containing an integer value greater than or equal to one',
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
        random_increment => 10,
        character_substitutions => {},
    }
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
#              4. OPTIONAL - a truthy value to enter debug mode
# Throws     : Croaks if the function is called in an invalid way, or with an
#              invalid config
# Notes      : 
# See Also   : For valid configuarion options see POD documentation below
sub new{
    my $class = shift;
    my $dictionary_path = shift;
    my $preset = shift;
    my $preset_override = shift;
    my $debug = shift;
    
    # validate args
    unless($class && $class eq $_CLASS){
        croak((caller 0)[3].'() - invalid invocation of constructor');
    }
    unless(defined $dictionary_path && -f $dictionary_path){
        croak((caller 0)[3].'() - a valid dictionary path must be passed as the first argument');
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
                croak((caller 0)[3]."() - invalid arguments - preset '$preset' does not exist");
            }
            
            # if overrides are defined, make sure they are hashrefs
            if(defined $preset_override){
                unless(ref $preset_override eq 'HASH'){
                    croak((caller 0)[3].'() - invalid arguments - if present, third argument must be a hashref');
                }
            }
            
            # load the preset
            $config = $_CLASS->preset_config($preset, $preset_override);
        }elsif(ref $preset eq 'HASH'){
            # we were passed a hashref, so use it as the config
            $config = $preset;
        }else{
            croak((caller 0)[3].'() - invalid argument - if present, the second argument must be a scalar or a hashref');
        }
    }else{
        $config = $_CLASS->default_config();
    }
    
    # initialise the object
    my $instance = {
        # 'public' instance variables
        debug => 0,
        # 'PRIVATE' internal variables
        _CONFIG => {},
        _DICTIONARY_PATH => q{}, # the path to the dictionary hashref
        _CACHE_DICTIONARY_FULL => [], # a cache of all words found in the dictionary file
        _CACHE_DICTIONARY_LIMITED => [], # a cache of all the words found in the dictionary file that meet the length criteria
        _CACHE_RANDOM => [], # a cache of random numbers (as floating points between 0 and 1)
    };
    if($debug){
        $instance->{debug} = 1;
    }
    bless $instance, $class;
    
    # load the config
    $instance->config($config);
    
    # load the dictionary (can't be done until the config is loaded)
    $instance->dictionary($dictionary_path);
    
    # if debugging, print out meta data
    if($debug){
        print "Initialised XKPasswd Instance with the following config:\n";
        print $instance->config_string();
        print "Cache Status:\n";
        print $instance->caches_state();
    }
    
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
        croak((caller 0)[3].'() - invalid invocation of class method');
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(ref $preset eq q{}){
        croak((caller 0)[3].'() - invalid args - if present, the first argument must be a scalar');
    }
    unless(defined $_PRESETS->{$preset}){
        croak((caller 0)[3]."() - preset '$preset' does not exist");
    }
    if(defined $overrides){
        unless(ref $overrides eq 'HASH'){
            croak((caller 0)[3].'() - invalid args, overrides must be passed as a hashref');
        }
    }
    
    # start by loading the preset
    my $config = $_CLASS->clone_config($_PRESETS->{$preset});
    
    # if overrides were passed, apply them and validate
    if(defined $overrides){
        foreach my $key (keys %{$overrides}){
            # ensure the key is valid - skip it if not
            unless(defined $_KEYS->{$key}){
                carp("Skinning invalid key=$key");
                next;
            }
            
            # ensure the value is valid
            eval{
                $_CLASS->_validate_key($key, $overrides->{$key}, 1); # returns 1 if valid
            }or do{
                carp("Skinning key=$key because of invalid value. Expected: $_KEYS->{$key}->{desc}");
                next;
            };
            
            # save the key into the config
            $config->{$key} = $overrides->{$key};
        }
        unless($_CLASS->is_valid_config($config)){
            croak('The default config combined with the specified overrides has resulted in an inalid config');
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(defined $config && $_CLASS->is_valid_config($config)){
        croak((caller 0)[3].'() - invalid args - a valid config hashref must be passed');
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
    $clone->{symbol_alphabet} = [];
    foreach my $symbol (@{$config->{symbol_alphabet}}){
        push @{$clone->{symbol_alphabet}}, $symbol;
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless($config && ref $config eq 'HASH'){
        croak((caller 0)[3].'() - invalid arguments');
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
    
    # if there is any kind of character padding, make sure a padding character is specified
    if($config->{padding_type} ne 'NONE'){
        unless(defined $config->{padding_character}){
            croak(qq{padding_type='$config->{padding_type}' requires padding_character be set}) if $croak;
            return 0;
        }
    }
    
    # if there is fixed character padding, make sure before and after are specified
    if($config->{padding_type} eq 'FIXED'){
        unless(defined $config->{padding_characters_before} && defined $config->{padding_characters_after}){
            croak(q{padding_type='FIXED' requires padding_characters_before & padding_characters_after be set}) if $croak;
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(defined $config && ref $config eq 'HASH'){
        croak((caller 0)[3].'() - invalid arguments');
    }
    
    # assemble the string to return
    my $ans = q{};
    foreach my $key (sort keys %{$_KEYS}){
        # skip undefined keys
        next unless defined $config->{$key};
        
        # make sure the key has the expected type
        unless(ref $config->{$key} eq $_KEYS->{$key}->{ref}){
            carp((caller 0)[3]."() - unexpected key type for key=$key (expected ref='$_KEYS->{$key}->{ref}', got ref='".ref $config->{$key}.q{')});
            next;
        }
        
        # process the key
        ## no critic (ProhibitCascadingIfElse);
        if($_KEYS->{$key}->{ref} eq q{}){
            # the key is a scalar
            $ans .= $key.q{=}.$config->{$key}.qq{\n};
        }elsif($_KEYS->{$key}->{ref} eq 'ARRAY'){
            # the key is an array ref
            $ans .= "$key=[";
            $ans .= join q{, }, sort @{$config->{$key}};
            $ans .= "]\n";
        }elsif($_KEYS->{$key}->{ref} eq 'HASH'){
            $ans .= "$key={";
            my @parts = ();
            foreach my $subkey (sort keys %{$config->{$key}}){
                push @parts, "$subkey=$config->{$key}->{$subkey}";
            }
            $ans .= join q{, }, @parts;
            $ans .= "}\n";
        }elsif($_KEYS->{$key}->{ref} eq 'CODE'){
            $ans .= $key.q{=}.$config->{$key}.qq{\n};
        }else{
            # this should never happen, but just in case, Confess (makes it easier to find than carping)
            confess((caller 0)[3]."() - encounterd an un-handled key type ($_KEYS->{$key}->{ref}) for key=$key - skipping key");
        }
        ## use critic
    }
    
    # return the string
    return $ans;
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $path)){
        # we are a getter, so just return
        return $self->{_DICTIONARY_PATH};
    }else{
        # we are a setter, so try load the dictionary
        
        # croak if we are called before the config has been loaded into the instance
        unless(defined $self->{_CONFIG}->{word_length_min} && $self->{_CONFIG}->{word_length_max}){
            croak((caller 0)[3].'() - Failed to load dictionary file - config has not been loaded yet');
        }
        
        # parse the file
        my @cache_full = $_CLASS->_parse_words_file($path);
    
        # generate the valid word cache - croaks if too few words left after filtering
        my @cache_limited = $_CLASS->_filter_word_list(\@cache_full, $self->{_CONFIG}->{word_length_min}, $self->{_CONFIG}->{word_length_max});
    
        # if we got here all is well, so save the new path and caches into the object
        $self->{_DICTIONARY_PATH} = $path;
        $self->{_CACHE_DICTIONARY_FULL} = [@cache_full];
        $self->{_CACHE_DICTIONARY_LIMITED} = [@cache_limited];
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $config)){
        # we are a getter - simply return a clone of our config
        return $self._clone_config();
    }else{
        # we are a setter
        
        # ensure the config passed is a hashref
        unless($config && ref $config eq 'HASH'){
            croak((caller 0)[3].'() - invalid arguments - the config passed must be a hashref');
        }
        
        # validate the passed config hashref
        eval{
            $_CLASS->is_valid_config($config, 1); # returns 1 if valid
        }or do{
            my $msg = (caller 0)[3].'() - invoked with invalid config';
            if($self->{debug}){
                $msg .= " ($EVAL_ERROR)";
            }
            croak($msg);
        };
        
        # save a clone of the passed config into the instance
        $self->{_CONFIG} = $_CLASS->clone_config($config);
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $new_keys && ref $new_keys eq 'HASH'){
        croak((caller 0)[3].'() - invalid arguments - the new config keys must be passed as a hashref');
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
            croak((caller 0)[3]."() - invalid new value for key=$key");
        }
        
        # update the key in the new config
        $new_config->{$key} = $new_keys->{$key};
        $num_keys_updated++;
        print 'DEBUG - '.(caller 0)[3]."() - updated $key to new value\n" if $self->{debug};
    }
    print 'DEBUG - '.(caller 0)[3]."() - updated $num_keys_updated keys\n" if $self->{debug};
    
    # validate the merged config
    unless($_CLASS->is_valid_config($new_config)){
        croak((caller 0)[3].'() - updated config is invalid');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
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
# Returns    : a passowrd as a string
# Arguments  : NONE
# Throws     : Croaks on invalid invocation or on error generating the password
# Notes      :
# See Also   :
sub password{
    my $self = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS)){
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    #
    # Generate the password
    #
    my $password = q{};
    eval{
        #
        # start by generating the needed parts of the password
        #
        print 'DEBUG - '.(caller 0)[3]."() - starting to generate random words\n" if $self->{debug};
        my @words = $self->_random_words();
        print 'DEBUG - '.(caller 0)[3].'() - got random words='.(join q{, }, @words)."\n" if $self->{debug};
        $self->_transform_case(\@words);
        $self->_substitute_characters(\@words); # TO DO
        my $separator = $self->_separator();
        my $pad_char = $self->_padding_char($separator);
        
        #
        # Then assemble the finished password
        #
        
        # start with the words and the separator
        $password = join $separator, @words;
        
        # next add the numbers front and back
        if($self->{_CONFIG}->{padding_digits_before} > 0){
            $password = $self->_random_digits($self->{_CONFIG}->{padding_digits_before}).$separator.$password;
        }
        if($self->{_CONFIG}->{padding_digits_after} > 0){
            $password = $password.$separator.$self->_random_digits($self->{_CONFIG}->{padding_digits_before});
        }
        
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
        1; # ensure true evaluation on successful execution
    }or do{
        croak("Failed to generate password with the following error: $EVAL_ERROR");
    };
    
    # return the finished password
    return $password;
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
#              4. OPTIONAL - a truthy value to enter debug mode
# Throws     : Croaks on error
# Notes      :
# See Also   :
sub xkpasswd{
    my $dictionary_path = shift;
    my $preset = shift;
    my $preset_override = shift;
    my $debug = shift;
    
    # try initialise an xkpasswd object
    my $xkpasswd;
    eval{
        $xkpasswd = $_CLASS->new($dictionary_path, $preset, $preset_override, $debug);
        1; # ensure truthy evaliation on successful execution
    } or do {
        croak("Failed to generate password with the following error: $EVAL_ERROR");
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
        croak((caller 0)[3].'() - invalid args - must request at least 1 password');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # build the clone
    my $clone = $_CLASS->clone_config($self->{_CONFIG});
    
    # if, and only if, debugging, validate the cloned config so errors in the
    # cloning code will trigger an exception
    if($self->{debug}){
        eval{
            $_CLASS->is_valid_config($clone, 1); # returns 1 if valid
        }or do{
            croak((caller 0)[3].'() - cloning error ('.$EVAL_ERROR.')');
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(defined $key && ref $key eq q{} && defined $val){
        croak((caller 0)[3].'() - invoked with invalid args');
    }
    
    # make sure the key exists
    unless(defined $_KEYS->{$key}){
        carp((caller 0)[3]."() - called with invalid key=$key") if $croak;
        return 0;
    }
    
    # make sure the value is of the correct type
    unless(ref $val eq $_KEYS->{$key}->{ref}){
        croak("Invalid type for key=$key. Expected: ".$_KEYS->{$key}->{desc}) if $croak;
        return 0;
    }
    
    # make sure the value passes the validation function for the key
    unless($_KEYS->{$key}->{validate}->($val)){
        croak("Invalid value for key=$key. Expected: ".$_KEYS->{$key}->{desc}) if $croak;
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(defined $path && ref $path eq q{} && -f $path){
        croak((caller 0)[3].'() - invoked with invalid file path');
    }
    
    # slurp the words file
    open my $WORDSFILE, '<', $path or croak("failed to open words file at $path");
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
        croak((caller 0)[3].'() - invalid invocation of class method');
    }
    unless(defined $word_list_ref && ref $word_list_ref eq q{ARRAY}){
        croak((caller 0)[3].'() - invoked with invalid word list');
    }
    unless(defined $min_len && ref $min_len eq q{} && $min_len =~ m/^\d+$/sx && $min_len > 3){
        croak((caller 0)[3].'() - invoked with invalid minimum word length');
    }
    unless(defined $max_len && ref $max_len eq q{} && $max_len =~ m/^\d+$/sx && $max_len >= $min_len){
        croak((caller 0)[3].'() - invoked with invalid maximum word length');
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
    
    # ensure we got enough words
    my $alen = scalar @ans;
    unless($alen >= $MIN_WORDS){
        croak("Too few valid words in the dictionary file (need at least $MIN_WORDS, got $alen)");
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $max && $max =~ m/^\d+$/sx && $max > 0){
        croak((caller 0)[3].'() - invoked with invalid random limit');
    }
    
    # calculate the random number
    my $ans = ($self->_rand() * 1_000_000) % $max;
    
    # return it
    print 'DEBUG - '.(caller 0)[3]."() - returning $ans (max=$max)\n" if $self->{debug};
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $num && $num =~ m/^\d+$/sx && $num > 0){
        croak((caller 0)[3].'() - invoked with invalid number of digits');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # get the next random number from the cache
    my $num = shift @{$self->{_CACHE_RANDOM}};
    if(!defined $num){
        # the cache was empty - so try top up the random cache - could croak
        print 'DEBUG - '.(caller 0)[3]."() - random cache empty - attempting to replenish\n" if $self->{debug};
        $self->_increment_random_cache();
        
        # try shift again
        $num = shift @{$self->{_CACHE_RANDOM}};
    }
    
    # make sure we got a valid random number
    unless(defined $num && $num =~ m/^\d+([.]\d+)?$/sx && $num >= 0 && $num <= 1){
        croak((caller 0)[3].'() - found invalid entry in random cache');
    }
    
    # return the random number
    print 'DEBUG - '.(caller 0)[3]."() - returning $num\n" if $self->{debug};
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # genereate the random numbers
    my @random_numbers = &{$self->{_CONFIG}->{random_function}}($self->{_CONFIG}->{random_increment});
    print 'DEBUG - '.(caller 0)[3].'() - generated '.(scalar @random_numbers).' random numbers ('.(join q{, }, @random_numbers).")\n" if $self->{debug};
    
    # validate them
    unless((scalar @random_numbers) == $self->{_CONFIG}->{random_increment}){
        croak((caller 0)[3].'() - random function did not return the correct number of random numbers');
    }
    foreach my $num (@random_numbers){
        unless($num =~ m/^1|(0([.]\d+)?)$/sx){
            croak((caller 0)[3]."() - random function returned and invalid value ($num)");
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    
    # get the random words
    my @ans = ();
    print 'DEBUG - '.(caller 0)[3].'() - about to generate '.$self->{_CONFIG}->{num_words}." words\n" if $self->{debug};
    while ((scalar @ans) < $self->{_CONFIG}->{num_words}){
        my $word = $self->{_CACHE_DICTIONARY_LIMITED}->[$self->_random_int(scalar @{$self->{_CACHE_DICTIONARY_LIMITED}})];
        print 'DEBUG - '.(caller 0)[3].'() - generate word='.$word."\n" if $self->{debug};
        push @ans, $word;
    }
    
    # return the list of random words
    print 'DEBUG - '.(caller 0)[3].'() - returning '.(scalar @ans)." words\n" if $self->{debug};
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $sep){
        croak((caller 0)[3].'() - no separator character passed');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $words_ref && ref $words_ref eq 'ARRAY'){
        croak((caller 0)[3].'() - no words array reference passed');
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
        croak((caller 0)[3].'() - invalid invocation of instance method');
    }
    unless(defined $words_ref && ref $words_ref eq 'ARRAY'){
        croak((caller 0)[3].'() - no words array reference passed');
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

    # get a default config hashref
    my $config = XKPasswd->default_config();

    # make any desired alterations
    $config->{dictionary_file_path} = '/usr/share/dict/words';

    # instantiate an XKPasswd object
    my $xkpasswd = XKPasswd->new($config);

    # TO DO - finish example

=head1 DESCRIPTION

A secure memorable password generator inspired by the wonderful XKCD webcomic
L<http://www.xkcd.com/> and Steve Gibson's Password Haystacks page
L<https://www.grc.com/haystack.htm>. This is the Perl library that powers
L<https://www.xkpasswd.net>.

=head2 PHILOSOPHY

The basic idea behind this password generator is that in this modern age of
fast password crackers, the only secure password is a long password. Rather
than assembling a password from an alphabet consisting of 26 lower case
characters, 26 upper case characters, ten digits, and a few symbols, why
not use a dictionary file as a massive alphabet containing hundreds or
even thousands of words, then combine just a few of those with a randomly
chosen but easy to remember symbol character, and perhaps pad it front
and back with a few digits and repeated symbols.

You only need to remember the words, two symbols, and, if you choose, a few
digits, and assuming an average word length of 6, you end up with a 37
character password something like:

    ==67^Become^Matter^Finger^Animal^24==

For comparison, here is a truly random eight character password:

    RClo^9+e

Most people will find the former easier to memorise than the latter, even
though it's much longer, and much much harder to guess. If you plug both
of the above example passwords into Password Haystacks
(L<https://www.grc.com/haystack.htm>), you'll see that with the best modern
hardware (as of 2014), the truly random 8 character password could be
cracked in minutes, while the 37 character password would take trillions of
times the age of the universe to crack. That's a very definite improvement!

Given the fact that we should all be using separate passwords on every site,
many people now use password managers like LastPass or 1Password, so arguably
the memorability of our passwords has become irrelevant. However, with a
password manager, your entire security hinges on the quality of your master
password, so you need to make it a good one! Also, when you are not on your
own computer, you may need to read your password from your phone or other
mobile device and manually enter it. You'll find a long word-based password
to be much easier to enter than a long truly random password.

=head2 THE MATHS

When describing the philosophy of XKPasswod we used the following two sample
passwords:

=over 4

=item *

C<RClo^9+e> (eight random alphanumeric characters with mixed case and including
symbols)

=item *

C<==67^Become^Matter^Finger^Animal^24==> (four random words separate with a
random character, padded with four random digits, and a random symbol)

=back

If we only consider brute force attacks, then there are 6.70 x 10^15
permutations for the random 8 character password, and 1.51 x 10^73 permutations
for the sample XKPasswd-style password. Clearly, the latter is trillions of
times better!

This calculation assumes that the attacker does not know that you used XKPasswd
to generate your password. This is a very reasonable assumption, but, for the
sake or argument, let's assume it doesn't hold up. Let's assume the absolute
worst-case scenario, and calculate the permutations an attacker would have to
go through to guess your password.

The worst-case scenario is that the attacker doesn't just know that you used
XKPasswd to generate your password, but also the exact settings used, and, the
dictionary file the words were chosen from. This is not actually a realistic
scenario, because any attacker in a position to know all this probably has
un-fettered access to your systems anyway, and so wouldn't need to crack your
passwords! However, it serves as a very good worst-case for our calculations.

Given that the attackers knows that our password was generated by picking four
random words, picking a single random symbol to act as a separator, picking
four random digits, and finally picking one more random symbol to pad the front
and back of the password with, how much randomness is left?

To do the math we first need to tie down the size of our dictionary, and the
number of symbols to be choosing from. To make the math easy, lets say our
dictionary contains one thousand words, and we are choosing symbols from a set
of ten.

What this means is that we are picking four words from a possible 1,000, four
digits from a possible ten, and two symbols from a possible ten. I.e.:

1000^4 * 10^4 * 10^2

This gives 1 x 10^18 permutations, which is three orders of magnitude more
than for the 8 character random password. In other words, even in the worst
possible scenario, assuming a good dictionary, and a reasonable configuration,
XKPasswd is better than an 8 digit random password.

To get the worst-case scenario down to the same order of magnitude as the
eight digit random password, the dictionary file would have to be reduced
to about 100 words.

A more realistic scenario would be that the attacker might know you used
XKPasswd, but not what dictionary you used, or what settings you used. In this
case the attacker will need to try many more possible passwords to cover
variations in padding length, dictionary content, and text transformations.
The math on this is too complex for this manual, but will fall somewhere 
between the 1 X 10^18 permutations of the worst-case, and the 1.51 x 10^73
permutations of the best-case.

=head1 SUBROUTINES/METHODS

=head2 DICTIONARY FILES

XKPasswd instances use text files as the source for the list of words to
randomly choose from when generating the password. Each instance uses one text
file, referred to as the Dictionary File, and specified via the
C<dictionary_file_path> config variable.

Dictionary files should contain one word per line. Words shorter than four
letters will be ignored, as will all lines starting with the # symbol.

This format is the same as that of the standard Unix Words file, usually found
at C</usr/share/dict/words> on Unix and Linux operating systems (including OS
X).

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
than or equal to 1. The default is 10.

=item *

C<separator_alphabet> - this key is optional. It can be used to override
the contents of C<symbol_alphabet> when C<separator_character> is set to
C<RANDOM>.

=item *

C<separator_character> - the character to use to separate the words in the
generated password. Must be a scalar, and acceptable values are a single
character, or, the special values C<NONE> (indicating that no separator should
be used), or C<RANDOM>, indicating that a character should be chosen at random
from the C<symbol_alphabet>. The default value returned by C<default_config()>
is C<RANDOM>.

=item *

C<symbol_alphabet> - an arrayref containing at least five single characters as
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

TO DO

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

=head3 C<xkpasswd()>

    my $password = xkpasswd('mydict.txt');
    
This function call is equivalent to the following Object-Oriented code:

    my $xkpasswd = XKPasswd->new('mydict.txt');
    my $password = $xkpasswd->password();
    
This function passes it's arguments through to the constructor, so all arguments
that are valid in C<new()> are valid here.

This function Croaks if there is a problem generating the password.


=head2 CONSTRUCTOR

    # create an instance with the default config
    my $xkpasswd_instance = XKPasswd->new('dict.txt');
    
    # create an instance with the preset 'XKCD'
    my $xkpasswd_instance = XKPasswd->new('dict.txt', 'XKCD');
    
    #create an instance based on the preset 'XKCD', but with one config key
    # overridden (case_transform)
    my $xkpasswd_instance = XKPasswd->new('dict.txt', 'XKCD', {case_transform => 'INVERT'});
    
    # create an instance with a custom config hashref
    my $xkpasswd_instance = XKPasswd->new('dict.txt' $config_hashref);

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

=head2 'CLASS' FUNCTIONS

All 'class functions' (for want of a better term) must be invoked via the
package name, or they will croak.

=head3 clone_config()

    my $clone = XKPasswd->clone_config($config);
    
This function must be passed a valid config hashref as the first argument or it
will croak. The function returns a hashref.

=head3 config_to_string()

    my $config_string = XKPasswd->config_to_string($config);
    
This function returns the content of the passed config hashref as a scalar
string. The function must be passed a valid config hashref or it will croak.

=head3 default_config()

    my $config = XKPasswd->default_config();

This function returns a hashref containing a config with default values.

This function can optionally be called with a single argument, a hashref
containing keys with values to override the defaults with.

    my $config = XKPasswd->default_config({dictionary_file_path => 'mydict.txt'});
    
When overrides are present, the function will carp if an invalid key or value is
passed, and croak if the resulting merged config is invalid.

This function is a shortcut for C<preset_config()>, and the above examples are
equivalent to the following:

    my $config = XKPasswd->preset_config('DEFAULT');
    my $config = XKPasswd->default_config('DEFAULT', {dictionary_file_path => 'mydict.txt'});

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

The first argument this function accpeps is the name of the desired preset as a
scalar. If an invalid name is passed, the function will carp. If no preset is
passed the preset C<'DEFAULT'> is assumed.

This function can optionally accept a second argument, a hashref
containing keys with values to override the defaults with.

    my $config = XKPasswd->preset_config('XKCD', {case_transform => 'INVERT'});
    
When overrides are present, the function will carp if an invalid key or value is
passed, and croak if the resulting merged config is invalid.

=head2 INSTANCE FUNCTIONS

Instance functions must be called on an XKPasswd object or they will croak.

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
    $xkpasswd_instance->dictionary('dict.txt');
    
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

=head3 update_config()

    $xkpasswd_instance->update_config({separator_character => '+'});
    
The function updates the config within an XKPasswd instance. A hashref with the
config options to be changed must be passed. The function returns a reference to
the instance to enable function chaining. The function will croak if the updated
config would be invalid in some way. Note that if this happens the running
config will not have been altered in any way.

=head1 DIAGNOSTICS

TO DO

=head1 CONFIGURATION AND ENVIRONMENT

TO DO - may not be needed, depends on whether or not configuration file support
gets added

=head1 DEPENDENCIES

=over 4

=item *

C<Carp> - L<http://search.cpan.org/perldoc?Carp>

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