package Crypt::HSXKPasswd;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use Params::Validate qw( :all ); # for argument validation
use English qw( -no_match_vars ); # for more readable code
use Scalar::Util qw( blessed ); # for checking if a reference is blessed
use Math::Round; # for round()
use Math::BigInt; # for the massive numbers needed to store the permutations
use Types::Standard qw( :types ); # for basic type checking (Int Str etc.)
use Crypt::HSXKPasswd::Types qw( :types :is ); # for custom type checking
use Crypt::HSXKPasswd::Dictionary::Basic;
use Crypt::HSXKPasswd::RNG::Math_Random_Secure;
use Crypt::HSXKPasswd::RNG::Data_Entropy;
use Crypt::HSXKPasswd::RNG::DevUrandom;
use Crypt::HSXKPasswd::RNG::Basic;

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw( encode decode );
use Text::Unidecode; # for stripping accents from accented characters
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

# import (or not) optional modules
my $_CAN_STACK_TRACE = eval{
    require Devel::StackTrace; # for better error reporting when debugging
};
my $_CAN_JSON = eval{
    require JSON; # for JSON parsing
};
if($_CAN_JSON){
    import JSON; # exports encode_json, decode_json, to_json and from_json
}
eval{
    # the default dicrionary may not have been geneated using the Util module
    require Crypt::HSXKPasswd::Dictionary::EN_Default;
}or do{
    carp('WARNING - failed to load Crypt::HSXKPasswd::Dictionary::EN_Default');
};

## no critic (ProhibitAutomaticExportation);
use base qw( Exporter );
our @EXPORT = qw( hsxkpasswd );
## use critic

# Copyright (c) 2015, Bart Busschots T/A Bartificer Web Solutions All rights
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
use version; our $VERSION = qv('3.1_02');

# acceptable entropy levels
our $ENTROPY_MIN_BLIND = 78; # 78 bits - equivalent to 12 alpha numeric characters with mixed case and symbols
our $ENTROPY_MIN_SEEN = 52; # 52 bits - equivalent to 8 alpha numeric characters with mixed case and symbols
our $SUPRESS_ENTROPY_WARNINGS = 'NONE'; # valid values are 'NONE', 'ALL', 'SEEN', or 'BLIND' (invalid values treated like 'NONE')

# Logging configuration
our $LOG_STREAM = *STDERR; # default to logging to STDERR
our $LOG_ERRORS = 0; # default to not logging errors
our $DEBUG = 0; # default to not having debugging enabled

# utility variables
my $_CLASS = __PACKAGE__;
my $_DICTIONARY_BASE_CLASS = 'Crypt::HSXKPasswd::Dictionary';
my $_RNG_BASE_CLASS = 'Crypt::HSXKPasswd::RNG';

# config key definitions
my $_KEYS = {
    allow_accents => {
        req => 0,
        type => Value,
        desc => 'Any truthy or falsy scalar value',
    },
    symbol_alphabet => {
        req => 0,
        type => SymbolAlphabet,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    separator_alphabet => {
        req => 0,
        type => SymbolAlphabet,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    padding_alphabet => {
        req => 0,
        type => SymbolAlphabet,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    word_length_min => {
        req => 1,
        type => WordLength,
        desc => 'An integer greater than three',
    },
    word_length_max => {
        req => 1,
        type => WordLength,
        desc => 'An integer greater than three',
    },
    num_words => {
        req => 1,
        type => Type::Tiny->new(
            parent => Int,
            constraint => sub{
                return $_ >= 2;
            },
        ),
        desc => 'An integer greater than or equal to two',
    },
    separator_character => {
        req => 1,
        type => Type::Tiny->new(
            parent => Str,
            constraint => sub{
                return is_Symbol($_) || $_ =~ m/^(NONE)|(RANDOM)$/sx;
            },
        ),
        desc => q{A single character or one of the special values: 'NONE' or 'RANDOM'},
    },
    padding_digits_before => {
        req => 1,
        type => PositiveInteger,
        desc => 'An integer greater than or equal to zero',
    },
    padding_digits_after => {
        req => 1,
        type => PositiveInteger,
        desc => 'An integer greater than or equal to zero',
    },
    padding_type => {
        req => 1,
        type => Type::Tiny->new(
            parent => Str,
            constraint => sub{
                return $_ =~ m/^(NONE)|(FIXED)|(ADAPTIVE)$/sx;
            },
        ),
        desc => q{One of the values 'NONE', 'FIXED', or 'ADAPTIVE'},
    },
    padding_characters_before => {
        req => 0,
        type => PositiveInteger,
        desc => 'An integer greater than or equal to one',
    },
    padding_characters_after => {
        req => 0,
        type => PositiveInteger,
        desc => 'An integer greater than or equal to one',
    },
    pad_to_length => {
        req => 0,
        type => Type::Tiny->new(
            parent => Int,
            constraint => sub{
                return $_ >= 12;
            },
        ),
        desc => 'An integer greater than or equal to twelve',
    },
    padding_character => {
        req => 0,
        type => Type::Tiny->new(
            parent => Str,
            constraint => sub{
                return is_Symbol($_) || $_ =~ m/^(NONE)|(RANDOM)|(SEPARATOR)$/sx;
            },
        ),
        desc => q{A single character or one of the special values: 'NONE', 'RANDOM', or 'SEPARATOR'},
    },
    case_transform => {
        req => 0,
        type => Type::Tiny->new(
            parent => Enum[qw( NONE UPPER LOWER CAPITALISE INVERT ALTERNATE RANDOM )],
        ),
        desc => q{One of the values 'NONE' , 'UPPER', 'LOWER', 'CAPITALISE', 'INVERT', 'ALTERNATE', or 'RANDOM'},
    },
    character_substitutions => {
        req => 0,
        type => Type::Tiny->new(
            
        ),
        ref => 'HASH', # Hashref REF
        validate => sub {
            my $key = shift;
            foreach my $char (keys %{$key}){
                unless(ref $char eq q{} && $char =~ m/^\w$/sx){ return 0; } # single char key
                unless(ref $key->{$char} eq q{} && $key->{$char} =~ m/^\S+$/sx){ return 0; }
            }
            return 1;
        },
        desc => 'A hash ref mapping characters to their replacements - can be empty',
    },
};

# preset definitions
my $_PRESETS = {
    DEFAULT => {
        description => 'The default preset resulting in a password consisting of 3 random words of between 4 and 8 letters with alternating case separated by a random character, with two random digits before and after, and padded with two random characters front and back',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * - _ + = : | ~ ? / . ;}],
            word_length_min => 4,
            word_length_max => 8,
            num_words => 3,
            separator_character => 'RANDOM',
            padding_digits_before => 2,
            padding_digits_after => 2,
            padding_type => 'FIXED',
            padding_character => 'RANDOM',
            padding_characters_before => 2,
            padding_characters_after => 2,
            case_transform => 'ALTERNATE',
            allow_accents => 0,
        },
    },
    WEB32 => {
        description => q{A preset for websites that allow passwords up to 32 characteres long.},
        config => {
            padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
            allow_accents => 0,
        },
    },
    WEB16 => {
        description => 'A preset for websites that insit passwords not be longer than 16 characters.',
        config => {
            padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
            allow_accents => 0,
        },
    },
    WIFI => {
        description => 'A preset for generating 63 character long WPA2 keys (most routers allow 64 characters, but some only 63, hence the odd length).',
        config => {
            padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
            allow_accents => 0,
        },
    },
    APPLEID => {
        description => 'A preset respecting the many prerequisites Apple places on Apple ID passwords. The preset also limits itself to symbols found on the iOS letter and number keyboards (i.e. not the awkward to reach symbol keyboard)',
        config => {
            padding_alphabet => [qw{! ? @ &}],
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
            allow_accents => 0,
        },
    },
    NTLM => {
        description => 'A preset for 14 character Windows NTLMv1 password. WARNING - only use this preset if you have to, it is too short to be acceptably secure and will always generate entropy warnings for the case where the config and dictionary are known.',
        config => {
            padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
            allow_accents => 0,
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
            padding_alphabet => [qw{. ! ?}],
            padding_characters_before => 0,
            padding_characters_after => 1,
            case_transform => 'NONE',
            allow_accents => 0,
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
            allow_accents => 0,
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
# Arguments  : This function accepts the following named arguments - all
#              optional:
#              dictionary - an object that inherits from
#                  Crypt::HSXKPasswd::Dictionary
#              dictionary_list - an array ref of words to use as a dictionary.
#              dictionary_file - the path to a dictionary file.
#              dictionary_file_encoding - the encoding to use when loading the
#                  dictionary file, defaults to UTF-8.
#              preset - the preset to use
#              preset_overrides - a hashref of config options to override.
#                  Ignored unless preset is set, and in use.
#              config - a config hashref.
#              config_json - a config as a JSON string (requires that the JSON
#                  module be installed)
#              rng - an object that inherits from Crypt::HSXKPasswd::RNG
# Throws     : Croaks if the function is called in an invalid way, called with
#              invalid args, or called with a JSON string when JSON is not
#              installed.
# Notes      : The order of preference for word sources is dictionary, then
#              dictionary_list, then dictionary_file. If none are specified,
#              then an instance of Crypt::HSXKPasswd::Dictionary::EN_Default
#              will be used.
#              The order of preference for the configuration source is config
#              then config_json, then preset. If no configuration source is
#              specified, then the preset 'DEFAULT' is used.
#              If no RNG is passed, _best_available_rng() will be used to
#              instantiate and instance of the most secure RNG usable on the
#              system.
# See Also   : For valid configuarion options see POD documentation below
sub new{
    my @args = @_;
    my $class = shift @args;
    my %args = validate(
        @args, {
            dictionary => {isa => $_DICTIONARY_BASE_CLASS, optional => 1},
            dictionary_list => {type => ARRAYREF, optional => 1},
            dictionary_file => {type => SCALAR, optional => 1},
            dictionary_file_encoding => {type => SCALAR, optional => 1, default => 'UTF-8'},
            config => {type => HASHREF, optional => 1},
            config_json => {type => SCALAR, optional => 1},
            preset => {type => SCALAR, optional => 1},
            preset_overrides => {type => HASHREF, optional => 1},
            rng => {isa => $_RNG_BASE_CLASS, optional => 1},
        }
    );
    
    my $preset = shift;
    my $preset_override = shift;
    
    # validate args
    _force_class($class);
    
    # before going any further, check the presets if debugging (doing later may cause an error before we test)
    if($DEBUG){
        $_CLASS->_check_presets();
    }
    
    # process the word source
    my $dictionary;
    if($args{dictionary}){
        $dictionary = $args{dictionary};
    }elsif($args{dictionary_list}){
        $dictionary = Crypt::HSXKPasswd::Dictionary::Basic->new($args{dictionary_list});
    }elsif($args{dictionary_file}){
        $dictionary = Crypt::HSXKPasswd::Dictionary::Basic->new($args{dictionary_file}, $args{dictionary_file_encoding});
    }else{
        $dictionary = Crypt::HSXKPasswd::Dictionary::EN_Default->new();
    }
    
    # process the config source
    my $config = {};
    if($args{config}){
        $config = $args{config};
    }elsif($args{config_json}){
        $config = $args{config_json}; # pass the string on, config() will deal with it
    }elsif($args{preset}){
        $config = $_CLASS->preset_config(uc $args{preset}, $args{preset_overrides});
    }else{
        $config = $_CLASS->default_config();
    }
    
    # process the random number source
    my $rng = {};
    if($args{rng}){
        $rng = $args{rng};
    }else{
        $rng = $_CLASS->_best_available_rng();
    }
    
    # initialise the object
    my $instance = {
        # 'public' instance variables (none so far)
        # 'PRIVATE' internal variables
        _CONFIG => {},
        _DICTIONARY_SOURCE => {}, # the dictionary object to source words from
        _RNG => {}, # the random number generator
        _CACHE_DICTIONARY_FULL => [], # a cache of all words found in the dictionary file
        _CACHE_DICTIONARY_LIMITED => [], # a cache of all the words found in the dictionary file that meet the length criteria
        _CACHE_CONTAINS_ACCENTS => 0, # a cache of whether or not the filtered word list contains words with accented letters
        _CACHE_ENTROPYSTATS => {}, # a cache of the entropy stats for the current combination of dictionary and config
        _CACHE_RANDOM => [], # a cache of random numbers (as floating points between 0 and 1)
        _PASSWORD_COUNTER => 0, # the number of passwords this instance has generated
    };
    bless $instance, $class;
    
    # load the config - will croak on invalid config
    $instance->config($config);
    
    # load the dictionary (can't be done until the config is loaded)
    $instance->dictionary($dictionary);
    
    # load the rng
    $instance->rng($rng);
    
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
# Purpose    : Get a list of defined config keys.
# Returns    : An array of strings.
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub defined_config_keys{
    my $class = shift;
    
    # validate args
    _force_class($class);
    
    # gather the list of config key names
    my @keys = sort keys %{$_KEYS};
    
    # return the list
    return @keys;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Return the specification for a given config key.
# Returns    : A hash indexed by 'required', 'type', and 'type_description'.
# Arguments  : 1) a valid config key name
# Throws     : Croaks on invalid invocation and args
# Notes      :
# See Also   :
sub config_key_definition{
    my $class = shift;
    my $key = shift;
    
    # validate arguments
    _force_class($class);
    unless($key && $_KEYS->{$key}){
        $_CLASS->_error("invalid arguments - a valid key must be passed as the first argument");
    }
    
    # assemble the hash
    my %definition = (
        required => $_KEYS->{$key}->{req},
        type => $_KEYS->{$key}->{type},
        type_description => $_KEYS->{$key}->{desc},
    );
    
    # return the hash
    return %definition;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Return a hash of all key definitions indexed by key name.
# Returns    : A hash of key defintions as returned by config_key_definition().
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   : config_key_definition()
sub config_key_definitions{
    my $class = shift;
    
    # validate arguments
    _force_class($class);
    
    # gather the definitions
    my %definitions = ();
    foreach my $key ($_CLASS->defined_config_keys()){
        $definitions{$key} = $_CLASS->config_key_definition($key);
    }
    
    # return the definitions
    return %definitions;
}

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
    _force_class($class);

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
    _force_class($class);
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
                $_CLASS->_warn("Skipping invalid key=$key");
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
# Purpose    : Resturn the presets defined in the Crypt::HSXKPasswd module as a
#              JSON string
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
    _force_class($class);
    
    # make sure JSON parsing is available
    unless($_CAN_JSON){
        $_CLASS->_error('You must install the JSON Perl module (http://search.cpan.org/perldoc?JSON) to use this function');
    }
    
    # assemble an object cotaining the presets with any keys that can't be
    #  converted to JSON removed
    my @defined_presets = $_CLASS->defined_presets();
    my $sanitised_presets = {};
    my $preset_descriptions = {};
    foreach my $preset_name (@defined_presets){
        $sanitised_presets->{$preset_name} = $_CLASS->preset_config($preset_name);
        $preset_descriptions->{$preset_name} = $_CLASS->preset_description($preset_name);
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
        $_CLASS->_error("failed to render presets as JSON string with error: $EVAL_ERROR");
    };
    
    # return the JSON string
    return $json_string;
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
    _force_class($class);
    unless(defined $config && $_CLASS->is_valid_config($config)){
        $_CLASS->_error('invalid args - a valid config hashref must be passed');
    }
    
    # start with a blank hashref
    my $clone = {};
    
    # copy over all the scalar keys
    KEY_TO_CLONE:
    foreach my $key (keys %{$_KEYS}){
        # skip the key if it is not defined in the config to clone
        next KEY_TO_CLONE unless defined $config->{$key};
        
        # skip non-scalar keys
        next KEY_TO_CLONE unless ref $config->{$key} eq q{};
        
        # copy the key to the clone
        $clone->{$key} = $config->{$key};
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
    if(defined $config->{padding_alphabet} && ref $config->{padding_alphabet} eq 'ARRAY'){
        $clone->{padding_alphabet} = [];
        foreach my $symbol (@{$config->{padding_alphabet}}){
            push @{$clone->{padding_alphabet}}, $symbol;
        }
    }
    if(defined $config->{character_substitutions}){
        $clone->{character_substitutions} = {};
        foreach my $key (keys %{$config->{character_substitutions}}){
            $clone->{character_substitutions}->{$key} = $config->{character_substitutions}->{$key};
        }
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
    _force_class($class);
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
            croak("key '$key' is required, but not defined") if $croak;
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
            croak("Invalid value specified for config key '$key'. Must Be: ".$_KEYS->{$key}->{desc}) if $croak;
            return 0;
        };
    }
    
    # finally, make sure all other requirements are met
    
    # if there is a need for a symbol alphabet, make sure one is defined
    if($config->{separator_character} eq 'RANDOM'){
        unless(defined $config->{symbol_alphabet} || defined $config->{separator_alphabet}){
            croak(qq{setting separator_character='$config->{separator_character}' requires that one of the config keys symbol_alphabet or separator_alphabet be set}) if $croak;
            return 0;
        }
    }
    
    # if there is any kind of character padding, make sure a padding character is specified
    if($config->{padding_type} ne 'NONE'){
        unless(defined $config->{padding_character}){
            croak(qq{setting padding_type='$config->{padding_type}' requires that the config key padding_character be set}) if $croak;
            return 0;
        }
        if($config->{padding_character} eq 'RANDOM'){
            unless(defined $config->{symbol_alphabet} || defined $config->{padding_alphabet}){
                croak(qq{setting padding_character='$config->{padding_character}' requires that one of the config keys symbol_alphabet or padding_alphabet be set}) if $croak;
            return 0;
            }
        }
    }
    
    # if there is fixed character padding, make sure before and after are specified, and at least one has a value greater than 1
    if($config->{padding_type} eq 'FIXED'){
        unless(defined $config->{padding_characters_before} && defined $config->{padding_characters_after}){
            croak(q{setting padding_type='FIXED' requires that both the config keys padding_characters_before and padding_characters_after be set}) if $croak;
            return 0;
        }
        unless($config->{padding_characters_before} + $config->{padding_characters_after} > 0){
            croak(q{setting padding_type='FIXED' requires that both the config keys padding_characters_before and padding_characters_after be set, and that at least one of them be set to a value greater than one (to specify that no padding be used, set the config key padding_type to 'NONE')}) if $croak;
            return 0;
        }
    }
    
    # if there is adaptive padding, make sure a length is specified
    if($config->{padding_type} eq 'ADAPTIVE'){
        unless(defined $config->{pad_to_length}){
            croak(q{setting padding_type='ADAPTIVE' requires that the config key pad_to_length be set}) if $croak;
            return 0;
        }
    }
    
    # if we got this far, all is well, so return true
    return 1;
}
## use critic

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Convert a config hashref to a JSON String
# Returns    : A scalar
# Arguments  : 1. A config hashref
# Throws     : Croaks on invalid invocation or with invalid args. Carps if there
#              are problems with the config hashref.
# Notes      : The function will croak unless the standard Perl JSON module is
#              installed.
# See Also   :
sub config_to_json{
    my $class = shift;
    my $config = shift;
    
    # validate the args
    _force_class($class);
    unless(defined $config && ref $config eq 'HASH'){
        $_CLASS->_error('invalid arguments');
    }
    
    # make sure JSON parsing is available
    unless($_CAN_JSON){
        $_CLASS->_error('You must install the JSON Perl module (http://search.cpan.org/perldoc?JSON) before you can pass the config as a JSON stirng');
    }
    
    # try render the config to a JSON string
    my $ans = q{};
    eval{
        $ans = encode_json($config);
        1; # ensure a thurthy evaluation on successful execution
    }or do{
        $_CLASS->_error("Failed to convert config to JSON stirng with error: $EVAL_ERROR");
    };
    
    # return the string
    return $ans;
}

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
    _force_class($class);
    unless(defined $config && ref $config eq 'HASH'){
        $_CLASS->_error('invalid arguments');
    }
    unless($_CLASS->is_valid_config($config)){
        $_CLASS->_error('invalid arguments - invalid config hashref passed');
    }
    
    # assemble the string to return
    my $ans = q{};
    CONFIG_KEY:
    foreach my $key (sort keys %{$_KEYS}){
        # skip undefined keys
        next CONFIG_KEY unless defined $config->{$key};
        
        # process the key
        if(ref $config->{$key} eq q{}){
            # the key is a scalar
            $ans .= $key.q{: '}.$config->{$key}.qq{'\n};
        }elsif(ref $config->{$key} eq 'ARRAY'){
            # the key is an array ref
            $ans .= "$key: [";
            my @parts = ();
            foreach my $subval (sort @{$config->{$key}}){
                push @parts, "'$subval'";
            }
            $ans .= join q{, }, @parts;
            $ans .= "]\n";
        }elsif(ref $config->{$key} eq 'HASH'){
            $ans .= "$key: {";
            my @parts = ();
            foreach my $subkey (sort keys %{$config->{$key}}){
                push @parts, "$subkey: '$config->{$key}->{$subkey}'";
            }
            $ans .= join q{, }, @parts;
            $ans .= "}\n";
        }else{
            # this should never happen, but just in case, throw a warning
            $_CLASS->_warn("the data for the key '$key' is of an un-expected type (".(ref $config->{$key}).') - skipping key');
        }
    }
    
    # return the string
    return $ans;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Return the description for a given preset
# Returns    : A scalar string
# Arguments  : 1. OPTIONAL - the name of the preset to get the description for,
#                 if no name is passed 'DEFAULT' is assumed
# Throws     : Croaks on invalid invocation or invalid args
# Notes      :
# See Also   :
sub preset_description{
    my $class = shift;
    my $preset = shift;
    
    # default blank presets to 'DEFAULT'
    $preset = 'DEFAULT' unless defined $preset;
    
    # convert preset names to upper case
    $preset = uc $preset;
    
    # validate the args
    _force_class($class);
    unless(ref $preset eq q{}){
        $_CLASS->_error('invalid args - if present, the first argument must be a scalar');
    }
    unless(defined $_PRESETS->{$preset}){
        $_CLASS->_error("preset '$preset' does not exist");
    }
    
    # return the description by loading the preset
    return $_PRESETS->{$preset}->{description};
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
    _force_class($class);
    
    # return the preset names
    my @preset_names = sort keys %{$_PRESETS};
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
    _force_class($class);
    
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

#####-SUB-#####################################################################
# Type       : CLASS
# Purpose    : Calculate the number of random numbers needed to genereate a
#              single password with a given config.
# Returns    : An integer
# Arguments  : 1) a valid config hashref
#              2) OPTIONAL - a true value to indicate that valiation of the
#                 config hashref should be skipped.
# Throws     : Croaks in invalid invocation, or invalid args
# Notes      :
# See Also   :
sub config_random_numbers_required{
    my $class = shift;
    my $config = shift;
    my $skip_validation = shift;
    
    # validate the args
    _force_class($class);
    unless(defined $config && ($skip_validation || $_CLASS->is_valid_config($config))){
        $_CLASS->_error('invalid args - a valid config hashref must be passed');
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
    
    # return the number
    return $num_rand;
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
    _force_class($class);
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
    my $num_rand = $_CLASS->config_random_numbers_required($config, 'skip valiation');
    
    # detect whether or not we need to carp about multi-character replacements
    if($config->{padding_type} ne 'ADAPTIVE' && !$suppres_warnings){
        if(defined $config->{character_substitutions}){
            CHAR_SUB:
            foreach my $char (keys %{$config->{character_substitutions}}){
                if(length $config->{character_substitutions}->{$char} > 1){
                    $_CLASS->_warn('maximum length may be underestimated. The loaded config contains at least one character substitution which replaces a single character with multiple characters.');
                    last CHAR_SUB;
                }
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
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Get the currently loaded dictionary object, or, load a new
#              dictionary
# Returns    : An clone of the loaded dictionary object, or, a reference to the
#              instance (to enable function chaining) if called as a setter
# Arguments  : 1. OPTIONAL - the source for the dictionary, can be:
#                 The path to a dictionary file
#                     -OR-
#                 A reference to an array of words
#                     -OR-
#                 An instance of a sub-class of Crypt::HSXKPasswd::Dictionary
#              2. OPTIONAL - the encoding to import the file with. The default
#                 is UTF-8 (ignored if the first argument is not a file path).
# Throws     : Croaks on invalid invocation, or, if there is a problem loading
#              a dictionary file
# Notes      :
# See Also   : For description of dictionary file format, see POD documentation
#              below
sub dictionary{
    my $self = shift;
    my $dictionary_source = shift;
    my $encoding = shift;
    
    # validate args
    _force_instance($self);
    unless($encoding){
        $encoding = 'UTF-8';
    }
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $dictionary_source)){
        # we are a getter, so just return
        return $self->{_DICTIONARY_SOURCE}->clone();
    }else{
        # we are a setter, so try load the dictionary
        
        # croak if we are called before the config has been loaded into the instance
        unless(defined $self->{_CONFIG}->{word_length_min} && $self->{_CONFIG}->{word_length_max}){
            $_CLASS->_error('failed to load dictionary file - config has not been loaded yet');
        }
        
        # get a dictionary instance
        my $new_dict;
        if($dictionary_source->isa($_DICTIONARY_BASE_CLASS)){
            $new_dict = $dictionary_source;
        }elsif(ref $dictionary_source eq q{} || ref $dictionary_source eq 'ARRAY'){
            $new_dict = Crypt::HSXKPasswd::Dictionary::Basic->new($dictionary_source, $encoding); # could throw an error
        }else{
            $_CLASS->_error('invalid args - must pass a valid dictinary, hashref, or file path');
        }
        
        # load the dictionary
        my @cache_full = @{$new_dict->word_list()};
    
        # generate the valid word cache - croaks if too few words left after filtering
        my @cache_limited = $_CLASS->_filter_word_list(\@cache_full, $self->{_CONFIG}->{word_length_min}, $self->{_CONFIG}->{word_length_max}, $self->{_CONFIG}->{allow_accents});
    
        # if we got here all is well, so save the new path and caches into the object
        $self->{_DICTIONARY_SOURCE} = $new_dict;
        $self->{_CACHE_DICTIONARY_FULL} = [@cache_full];
        $self->{_CACHE_DICTIONARY_LIMITED} = [@cache_limited];
        if($self->{_CONFIG}->{allow_accents}){
            $self->{_CACHE_CONTAINS_ACCENTS} = $_CLASS->_contains_accented_letters(\@cache_limited);
        }else{
            $self->{_CACHE_CONTAINS_ACCENTS} = 0;
        }
        
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
# Arguments  : 1. OPTIONAL - a configuration to load as:
#                 A config hashref
#                     -OR-
#                 A JSON string representing a config hashref
# Throws     : Croaks if the function is called in an invalid way, with invalid
#              arguments, or with an invalid config.
# Notes      : Passing a JSON string will cause the function to croak if perl's
#              JSON module is not installed.
# See Also   : For valid configuarion options see POD documentation below
sub config{
    my $self = shift;
    my $config_raw = shift;
    
    # validate args
    _force_instance($self);
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $config_raw)){
        # we are a getter - simply return a clone of our config
        return $self._clone_config();
    }else{
        # we are a setter
        
        # see what kind of argument we were passed, and behave appropriately
        my $config = {};
        if(ref $config_raw eq 'HASH'){
            # we  received a hashref, so just pass it on
            $config = $config_raw;
        }elsif(ref $config_raw eq q{}){
            # we received as string, so treat it as JSON
            
            # make sure JSON parsing is available
            unless($_CAN_JSON){
                $_CLASS->_error('You must install the JSON Perl module (http://search.cpan.org/perldoc?JSON) before you can pass the config as a JSON stirng');
            }
            
            # try parse the received string as JSON
            eval{
                $config = decode_json($config_raw);
                1; # ensure truthy evaluation on successful execution
            }or do{
                $_CLASS->_error("Failed to parse JSON config string with error: $EVAL_ERROR");
            };
        }else{
            $_CLASS->_error('invalid arguments - the config passed must be a hashref or a JSON string');
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

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Return the config of the currently running instance as a JSON
#              string.
# Returns    : A scalar.
# Arguments  : NONE
# Throws     : Croaks if invoked in an invalid way. Carps if it meets a key of a
#              type not accounted for in the code.
# Notes      : This function will carp if the JSON module is not available
# See Also   :
sub config_json{
    my $self = shift;
    
    # validate args
    _force_instance($self);
    
    # assemble the string to return
    my $ans = $_CLASS->config_to_json($self->{_CONFIG}); # will croak without JSON
    
    # return the string
    return $ans;
}

#####-SUB-#####################################################################
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
    _force_instance($self);
    
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
    _force_instance($self);
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
        @cache_limited = $_CLASS->_filter_word_list(\@cache_all, $new_config->{word_length_min}, $new_config->{word_length_max}, $new_config->{allow_accents});
    }
    
    # if we got here, all is well with the new config, so add it and the caches to the instance
    $self->{_CONFIG} = $new_config;
    $self->{_CACHE_DICTIONARY_LIMITED} = [@cache_limited];
    
    # update the instance's entropy cache
    $self->_update_entropystats_cache();
    
    # return a reference to self
    return $self;
}

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Get the currently loaded RNG object, or, load a new RNG
# Returns    : An instance to the loaded RNG object, or, a reference to the
#              instance (to enable function chaining) if called as a setter
# Arguments  : 1. OPTIONAL - an object that is a Crypt::HSXKPasswd::RNG
# Throws     : Croaks on invalid invocation, or invalid args
# Notes      :
# See Also   : 
sub rng{
    my $self = shift;
    my $rng = shift;
    
    # validate args
    _force_instance($self);
    
    # decide if we're a 'getter' or a 'setter'
    if(!(defined $rng)){
        # we are a getter, so just return
        return $self->{_RNG};
    }else{
        # we are a setter, so try load the RNG
        
        # croak if we were not passed a valid RNG
        unless(defined $rng && blessed($rng) && $rng->isa($_RNG_BASE_CLASS)){
            $_CLASS->_error('failed to set RNG - invalid value passed');
        }
        
        # set the RNG
        $self->{_RNG} = $rng;
        
        # empty the random cache
        $self->{_CACHE_RANDOM} = [];
    }
    
    # return a reference to self
    return 1;
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
    _force_instance($self);

    # generate the string
    my $ans = q{};
    $ans .= 'Loaded Words: '.(scalar @{$self->{_CACHE_DICTIONARY_LIMITED}}).' (out of '.(scalar @{$self->{_CACHE_DICTIONARY_FULL}}).' loaded from the file)'.qq{\n};
    $ans .= 'Cached Random Numbers: '.(scalar @{$self->{_CACHE_RANDOM}}).qq{\n};
    
    # return it
    return $ans;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Generaete a random password based on the object's loaded config
# Returns    : a passowrd as a scalar
# Arguments  : NONE
# Throws     : Croaks on invalid invocation or on error generating the password
# Notes      :
# See Also   :
sub password{
    my $self = shift;
    
    # validate args
    _force_instance($self);
    
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
    _force_instance($self);
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
# Purpose    : Generate n passwords and return them, and the entropy stats as a
#              JSON string.
# Returns    : A JSON string as a scalar representing a hashref contianing an
#              array of passwords indexed by 'passwords', and a hashref of
#              entropy stats indexed by 'stats'. The stats hashref itself is
#              indexed by: 'password_entropy_blind',
#              'password_permutations_blind', 'password_entropy_blind_min',
#              'password_entropy_blind_max', 'password_permutations_blind_max',
#              'password_entropy_seen' & 'password_permutations_seen'
# Arguments  : 1. the number of passwords to generate
# Throws     : Croaks on invalid invocation, invalid args, if there is a
#              problem generating the passwords, statistics, or converting the
#              results to a JSON string, or if the JSON module is not
#              available.
# Notes      : 
# See Also   :
sub passwords_json{
    my $self = shift;
    my $num_pws = shift;
    
    # validate args
    _force_instance($self);
    unless(defined $num_pws && ref $num_pws eq q{} && $num_pws =~ m/^\d+$/sx && $num_pws > 0){
        $_CLASS->_error('invalid args - must specify the number of passwords to generate as a positive integer');
    }
    
    # make sure JSON parsing is available
    unless($_CAN_JSON){
        $_CLASS->_error('You must install the JSON Perl module (http://search.cpan.org/perldoc?JSON) to use this function');
    }
    
    # try generate the passwords and stats - could croak
    my @passwords = $self->passwords($num_pws);
    my %stats = $self->stats();
    
    # generate the hashref containing the results
    my $response_obj = {
        passwords => [@passwords],
        stats => {
            password_entropy_blind => $stats{password_entropy_blind},
            password_permutations_blind => $_CLASS->_render_bigint($stats{password_permutations_blind}),
            password_entropy_blind_min => $stats{password_entropy_blind_min},
            password_permutations_blind_min => $_CLASS->_render_bigint($stats{password_permutations_blind_min}),
            password_entropy_blind_max => $stats{password_entropy_blind_max},
            password_permutations_blind_max => $_CLASS->_render_bigint($stats{password_permutations_blind_max}),
            password_entropy_seen => $stats{password_entropy_seen},
            password_permutations_seen => $_CLASS->_render_bigint($stats{password_permutations_seen}),
        },
    };
    
    # try generate the JSON string to return
    my $json_string = q{};
    eval{
        $json_string = JSON->new()->encode($response_obj);
        1; # ensure truthy evaluation on succesful execution
    }or do{
        $_CLASS->_error("Failed to render hashref as JSON string with error: $EVAL_ERROR");
    };
    
    # return the JSON string
    return $json_string;
}

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Return statistics about the instance
# Returns    : A hash of statistics indexed by the following keys:
#              * 'dictionary_source' - the source of the word list
#              * 'dictionary_words_total' - the total number of words loaded
#                from the dictionary file
#              * 'dictionary_words_filtered' - the number of words loaded from
#                the dictionary file that meet the lenght criteria set in the
#                loaded config
#              * 'dictionary_words_percent_available' - the percentage of the
#                total dictionary that is avialable for use with the loaded
#                config
#              * 'dictionary_filter_length_min' - the minimum length world
#                permitted by the filter
#              * 'dictionary_filter_length_max' - the maximum length world
#                permitted by the filter
#              * 'dictionary_contains_accents' - whether or not the filtered
#                list contains accented letters
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
#              * 'randomnumbers_source' - the name of the class used to
#                generate random numbers
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      : 
# See Also   : 
sub stats{
    my $self = shift;
    
    # validate args
    _force_instance($self);
    
    # create a hash to assemble all the stats into
    my %stats = ();
    
    # deal with the config-specific stats
    my %config_stats = $_CLASS->config_stats($self->{_CONFIG});
    $stats{password_length_min} = $config_stats{length_min};
    $stats{password_length_max} = $config_stats{length_max};
    $stats{password_random_numbers_required} = $config_stats{random_numbers_required};
    
    # deal with the dictionary file
    my %dict_stats = $self->_calcualte_dictionary_stats();
    $stats{dictionary_source} = $dict_stats{source};
    $stats{dictionary_words_total} = $dict_stats{num_words_total};
    $stats{dictionary_words_filtered} = $dict_stats{num_words_filtered};
    $stats{dictionary_words_percent_available} = $dict_stats{percent_words_available};
    $stats{dictionary_filter_length_min} = $dict_stats{filter_length_min};
    $stats{dictionary_filter_length_max} = $dict_stats{filter_length_max};
    $stats{dictionary_contains_accents} = $dict_stats{contains_accents};
    
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
    $stats{randomnumbers_source} = blessed($self->{_RNG});
    
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
    _force_instance($self);
    
    # assemble the response
    my %stats = $self->stats();
    my $status = q{};
    
    # the dictionary
    $status .= "*DICTIONARY*\n";
    $status .= "Source: $stats{dictionary_source}\n";
    $status .= "# words: $stats{dictionary_words_total}\n";
    $status .= "# words of valid length: $stats{dictionary_words_filtered} ($stats{dictionary_words_percent_available}%)\n";
    $status .= 'Contains Accented Characters: '.($stats{dictionary_contains_accents} ? 'YES' : 'NO')."\n";
    
    # the config
    $status .= "\n*CONFIG*\n";
    $status .= $self->config_string();
    
    # the random number cache
    $status .= "\n*RANDOM NUMBER CACHE*\n";
    $status .= "Random Number Generator: $stats{randomnumbers_source}\n";
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
    $status .= "# Random Numbers needed per-password: $stats{password_random_numbers_required}\n";
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
# Arguments  : See the constructor
# Throws     : Croaks on error
# Notes      : See the Constructor
# See Also   : For valid configuarion options see POD documentation below
sub hsxkpasswd{
    my @constructor_args = @_;
    
    # try initialise an xkpasswd object
    my $hsxkpasswd;
    eval{
        $hsxkpasswd = $_CLASS->new(@constructor_args);
        1; # ensure truthy evaliation on successful execution
    } or do {
        $_CLASS->_error("Failed to generate password with the following error: $EVAL_ERROR");
    };
    
    # genereate and return a password - could croak
    return $hsxkpasswd->password();
}

#
# 'Private' functions ---------------------------------------------------------
#

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Test the $class in a class function to make sure it was actually
#              invoked on the correct class.
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1) the $class variable to test
#              2) OPTIONAL - the class to compare against - defaults to $_CLASS.
#                 This option makes it possible for other classes in the package
#                 to use this function.
# Throws     : Croaks if $class is not valid
# Notes      :
# See Also   :
sub _force_class{
    my $test_class = shift;
    my $required_class = shift;
    $required_class = $_CLASS unless $required_class;
    
    unless(defined $test_class && ref $test_class eq q{} && $test_class eq $required_class){
        $_CLASS->_error("invalid invocation - must be invoked on the package $required_class", 1);
    }
    
    return 1;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Test the $self in an instance function to make sure it was
#              actually invoked as an instance function.
# Returns    : Always  returns 1 (to keep PerlCritic happy)
# Arguments  : 1) the $self variable to test
#              2) OPTIONAL - the class to test against - defaults to $_CLASS.
#                 This option makes it possible for other classes in the package
#                 to use this function.
# Throws     : Croaks if the $self variable is not an instance of this class.
# Notes      :
# See Also   :
sub _force_instance{
    my $test_self = shift;
    my $package = shift;
    $package = $_CLASS unless $package;
    
    unless(defined $test_self && blessed($test_self) && $test_self->isa($package)){
        $_CLASS->_error("invalid invocation - must be invoked on an instance of $package", 1);
    }
    
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function to log output from the module - SHOULD NEVER BE CALLED
#              DIRECTLY
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. the severity of the message (one of 'DEBUG', 'WARNING', or
#                 'ERROR')
#              2. the message to log
#              3. OPTIONAL - an increment to add to the argument to caller - to
#                 allow functions like _force_instance to invisibly invoke
#                 _debug(), _warn() & _error().
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
    my $stack_increment = shift;
    
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
    if(defined $stack_increment){
        unless(ref $stack_increment eq q{} && $stack_increment =~ m/^\d+$/sx){
            carp((caller 0)[3].'(): passed invalid stack increment - ignoring');
            $stack_increment = 0;
        }
    }else{
        $stack_increment = 0;
    }
    
    # figure out the correct index for the function that is really responsible
    my $caller_index = 2 + $stack_increment;
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
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'DEBUG'
# See Also   : _log()
sub _debug{
    my $class = shift;
    my $message = shift;
    my $stack_increment = shift;
    
    # validate the args
    _force_class($class);
    
    #pass the call on to _log
    return $_CLASS->_log('DEBUG', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function for issuing a warning
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the warning message to log
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'WARNING'
# See Also   : _log()
sub _warn{
    my $class = shift;
    my $message = shift;
    my $stack_increment = shift;
    
    # validate the args
    _force_class($class);
    
    #pass the call on to _log
    return $_CLASS->_log('WARNING', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Function for throwing an error
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the error message to log
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for _log() which invokes that function with a severity
#              of 'ERROR'
# See Also   : _log()
sub _error{
    my $class = shift;
    my $message = shift;
    my $stack_increment = shift;
    
    # validate the args
    _force_class($class);
    
    #pass the call on to _log
    return $_CLASS->_log('ERROR', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : CLASS ('PRIVATE')
# Purpose    : Return a reference to $_KEYS to make the variable directly
#              available to bundled packages.
# Returns    : A hashref
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub _key_definitions{
    my $class = shift;
    
    # validate args
    _force_class($class);
    
    # return the reference
    return $_KEYS;
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
    _force_instance($self);
    
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
    _force_class($class);
    unless(defined $key && ref $key eq q{} && defined $val){
        $_CLASS->_error('invoked with invalid args');
    }
    
    # make sure the key exists
    unless(defined $_KEYS->{$key}){
        carp("'$key' is not a valid config key name") if $croak;
        return 0;
    }
    
    # make sure the value passes the validation function for the key
    unless($_KEYS->{$key}->{type}->check($val)){
        croak("Invalid value specified for config key '$key'. Must be: ".$_KEYS->{$key}->{desc}) if $croak;
        return 0;
    }
    
    # if we got here, all is well, so return 1
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Filter a word list based on word length
# Returns    : An array of words as scalars.
# Arguments  : 1. a reference to the array of words to filter.
#              2. the minimum allowed word length
#              3. the maximum allowed word length
#              4. OPTIONAL - a truthy value to allow accented characters through
# Throws     : Croaks on invalid invocation, or if too few matching words found.
# Notes      : Unless the fourth argument is a truthy value, accents will be
#              stripped from the words.
# See Also   :
sub _filter_word_list{
    my $class = shift;
    my $word_list_ref = shift;
    my $min_len = shift;
    my $max_len = shift;
    my $allow_accents = shift;
    
    # validate the args
    _force_class($class);
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
        # calcualte the grapheme length
        my $grapheme_length = $_CLASS->_grapheme_length($word);
        
        # skip words shorter than the minimum
        next WORD if $grapheme_length < $min_len;
        
        # skip words longer than the maximum
        next WORD if $grapheme_length > $max_len;
        
        # strip accents unless they are explicitly allowed by the config
        unless($allow_accents){
            $word = unidecode($word);
        }
        
        # store the word in the filtered list
        push @ans, $word;
    }
    
    # return the list
    return @ans;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Determine whether a word list contains accented characters
# Returns    : 1 if the word list does contain accented characters, and 0 if it
#              does not.
# Arguments  : 1. A reference to an array of words to test
# Throws     : NOTHING
# Notes      :
# See Also   :
sub _contains_accented_letters{
    my $class = shift;
    my $word_list_ref = shift;
    
    # validate the args
    _force_class($class);
    unless(defined $word_list_ref && ref $word_list_ref eq q{ARRAY}){
        $_CLASS->_error('invoked with invalid word list');
    }
    
    # assume no accented characters, test until 1 is found
    my $accent_found = 0;
    WORD:
    foreach my $word (@{$word_list_ref}){
        # check for accents by stripping accents and comparing to original
        my $word_accents_stripped = unidecode($word);
        unless($word eq $word_accents_stripped){
            $accent_found = 1;
            last WORD;
        }
    }
    
    # return the list
    return $accent_found;
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
    _force_instance($self);
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
    _force_instance($self);
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
    _force_instance($self);
    
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
    _force_instance($self);
    
    # genereate the random numbers
    my @random_numbers = $self->{_RNG}->random_numbers($_CLASS->config_random_numbers_required($self->{_CONFIG}, 'skip valiation'));
    $_CLASS->_debug('generated '.(scalar @random_numbers).' random numbers ('.(join q{, }, @random_numbers).')');
    
    # validate them
    unless(scalar @random_numbers){
        $_CLASS->_error('random function did not return any random numbers');
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
    _force_instance($self);
    
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
    _force_instance($self);
    
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
    _force_instance($self);
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
        if(defined $self->{_CONFIG}->{padding_alphabet}){
            $padc = $self->{_CONFIG}->{padding_alphabet}->[$self->_random_int(scalar @{$self->{_CONFIG}->{padding_alphabet}})];
        }else{
            $padc = $self->{_CONFIG}->{symbol_alphabet}->[$self->_random_int(scalar @{$self->{_CONFIG}->{symbol_alphabet}})];
        }
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
    _force_instance($self);
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
    _force_instance($self);
    unless(defined $words_ref && ref $words_ref eq 'ARRAY'){
        $_CLASS->_error('no words array reference passed');
    }
    
    # if no substitutions are defined, do nothing
    unless(defined $self->{_CONFIG}->{character_substitutions} && (scalar keys %{$self->{_CONFIG}->{character_substitutions}})){
        return 1;
    }
    
    # If we got here, go ahead and apply the substitutions
    foreach my $i (0..((scalar @{$words_ref}) - 1)){
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
# Type       : CLASS (PRIVATE)
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
    _force_class($class);
    
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
    }
    if($num_problems == 0){
        $_CLASS->_debug('all presets OK');
    }
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS (PRIVATE)
# Purpose    : Create an RNG object that is as secure as possible.
# Returns    : An instance of a class that extends Crypt::HSXKPasswd::RNG.
# Arguments  : NONE
# Throws     : This function issues a warning if it has to fall back to
#              Crypt::HSXKPasswd::RNG::Basic.
# Notes      : This function works its way through the constructurs for the
#              following RNG classes in the following order, returing the first
#              successfully instantiate object:
#              1) Crypt::HSXKPasswd::RNG::Math_Random_Secure (using
#                 Math::Random::Secure)
#              2) Crypt::HSXKPasswd::RNG::Data_Entropy (using
#                 Data::Entropy::Algorithms)
#              3) Crypt::HSXKPasswd::RNG::DevUrandom (reads from /dev/urandom)
#              4) Crypt::HSXKPasswd::RNG::Basic (using Perl's built-in rand())
#              This ordering is based on security and speed - all but Basic are
#              good from a secutrity point of view, but Math::Random::Secure is
#              over six times faster than Data::Entropy::Algorithms, so it is
#              reduced to second place. Speed tested wth the commands:
#              time perl -MMath::Random::Secure -e "foreach my \$n (0..1000000){Math::Random::Secure::rand();}"
#              time perl -MData::Entropy::Algorithms -e "foreach my \$n (0..1000000){Data::Entropy::Algorithms::rand();}"
# See Also   :
sub _best_available_rng{
    my $class = shift;
    
    # validate the args
    _force_class($class);
    
    # try the good entropy sources in order
    my $rng;
    eval{
        $rng = Crypt::HSXKPasswd::RNG::Math_Random_Secure->new(); # will return a truthy value on success
    }or do{
        $_CLASS->_debug("Failed to instantiate a Crypt::HSXKPasswd::RNG::Math_Random_Secure object with error: $EVAL_ERROR");
    };
    return $rng if $rng;
    eval{
        $rng = Crypt::HSXKPasswd::RNG::Data_Entropy->new(); # will return a truthy value on success
    }or do{
        $_CLASS->_debug("Failed to instantiate a Crypt::HSXKPasswd::RNG::Data_Entropy object with error: $EVAL_ERROR");
    };
    return $rng if $rng;
    eval{
        $rng = Crypt::HSXKPasswd::RNG::DevUrandom->new(); # will return a truthy value on success
    }or do{
        $_CLASS->_debug("Failed to instantiate a Crypt::HSXKPasswd::RNG::DevUrandom object with error: $EVAL_ERROR");
    };
    return $rng if $rng;
    
    # if we got here, no secure RNGs were avaialable, so warn, then return an instance of the basic RNG
    $_CLASS->_warn(q{using Perl's built-in rand() function for random number generation. This is secure enough for most users, but you can get more secure random numbers by installing Math::Random::Secure or Data::Entropy::Algorithms});
    return Crypt::HSXKPasswd::RNG::Basic->new();
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
    _force_instance($self);
    
    my %ans = ();
    
    # get the password length details for the config
    my %config_stats = $_CLASS->config_stats($self->{_CONFIG}, 'supress errors');
    my $b_length_min = Math::BigInt->new($config_stats{length_min});
    my $b_length_max = Math::BigInt->new($config_stats{length_max});
    
    # calculate the blind permutations - (based purely on length and alphabet)
    my $alphabet_count = 26; # all passwords have at least one case of letters
    if($self->{_CONFIG}->{case_transform} =~ m/^(ALTERNATE)|(CAPITALISE)|(INVERT)|(RANDOM)$/sx){
        $alphabet_count += 26; # these configs guarantee a mix of cases
    }
    if($self->{_CONFIG}->{padding_digits_before} > 0 || $self->{_CONFIG}->{padding_digits_after} > 0){
        $alphabet_count += 10; # these configs guarantee digits in the mix
    }
    if($self->_passwords_will_contain_symbol() || $self->{_CACHE_CONTAINS_ACCENTS}){
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
        if(defined $self->{_CONFIG}->{padding_alphabet}){
            $b_seen_perms->bmul(Math::BigInt->new(scalar @{$self->{_CONFIG}->{padding_alphabet}}));
        }else{
            $b_seen_perms->bmul(Math::BigInt->new(scalar @{$self->{_CONFIG}->{symbol_alphabet}}));
        }
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
#              * 'source' - the source for the word list
#              * 'filter_length_min' - the minimum allowed word length
#              * 'filter_length_max' - the maximum allowed word length
#              * 'num_words_total' - the number of words in the un-filtered
#                dictionary file
#              * 'num_words_filtered' - the number of words after filtering on
#                size limitations
#              * 'percent_words_available' - the percentage of the un-filtered
#                words remaining in the filtered words list
#              * 'contains_accents' - whether or not the filtered word list
#                contains accented letter
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub _calcualte_dictionary_stats{
    my $self = shift;
    
    # validate args
    _force_instance($self);
    
    # create a hash to aggregate the stats into
    my %ans = ();
    
    # deal with agregate numbers first
    $ans{source} = $self->{_DICTIONARY_SOURCE}->source();
    $ans{num_words_total} = scalar @{$self->{_CACHE_DICTIONARY_FULL}};
    $ans{num_words_filtered} = scalar @{$self->{_CACHE_DICTIONARY_LIMITED}};
    $ans{percent_words_available} = round(($ans{num_words_filtered}/$ans{num_words_total}) * 100);
    $ans{filter_length_min} = $self->{_CONFIG}->{word_length_min};
    $ans{filter_length_max} = $self->{_CONFIG}->{word_length_max};
    $ans{contains_accents} = $self->{_CACHE_CONTAINS_ACCENTS};
    
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
    _force_instance($self);
    
    # assume no symbol, if we find one, set to 1
    my $symbol_used = 0;
    
    ## no critic (ProhibitEnumeratedClasses);
    # first check the padding
    if($self->{_CONFIG}->{padding_type} ne 'NONE'){
        if($self->{_CONFIG}->{padding_character} eq 'RANDOM'){
            if(defined $self->{_CONFIG}->{padding_alphabet}){
                my $all_pad_chars = join q{}, @{$self->{_CONFIG}->{padding_alphabet}};
                if($all_pad_chars =~ m/[^0-9a-zA-Z]/sx){ # if we have just one non-word character
                    $symbol_used = 1;
                }
            }else{
                my $all_pad_chars = join q{}, @{$self->{_CONFIG}->{symbol_alphabet}};
                if($all_pad_chars =~ m/[^0-9a-zA-Z]/sx){ # if we have just one non-word character
                    $symbol_used = 1;
                }
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
    _force_instance($self);
    
    # do nothing if the dictionary has not been loaded yet (should only happen while the constructor is building an instance)
    return 1 unless($self->{_DICTIONARY_SOURCE} && blessed($self->{_DICTIONARY_SOURCE}) && $self->{_DICTIONARY_SOURCE}->isa($_DICTIONARY_BASE_CLASS));
    
    # calculate and store the entropy stats
    my %stats = $self->_calculate_entropy_stats();
    $self->{_CACHE_ENTROPYSTATS} = \%stats;
    
    # warn if we need to
    unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'ALL'){
        # blind warning if needed
        unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'BLIND'){
            if($self->{_CACHE_ENTROPYSTATS}->{entropy_blind_min} < $ENTROPY_MIN_BLIND){
                $_CLASS->_warn('for brute force attacks, the combination of the loaded config and dictionary produces an entropy of '.$self->{_CACHE_ENTROPYSTATS}->{entropy_blind_min}.'bits, below the minimum recommended '.$ENTROPY_MIN_BLIND.'bits');
            }
        }
        
        # seen warnings if needed
        unless(uc $SUPRESS_ENTROPY_WARNINGS eq 'SEEN'){
            if($self->{_CACHE_ENTROPYSTATS}->{entropy_seen} < $ENTROPY_MIN_SEEN){
                $_CLASS->_warn('for attacks assuming full knowledge, the combination of the loaded config and dictionary produces an entropy of '.$self->{_CACHE_ENTROPYSTATS}->{entropy_seen}.'bits, below the minimum recommended '.$ENTROPY_MIN_SEEN.'bits');
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
    _force_class($class);
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
# Purpose    : Get the so-called 'grapheme length' of a unicode string, that is
#              to say, the length of a word where a letter with an accent counts
#              as a single letter.
# Returns    : An integer
# Arguments  : 1) the string to get the length of
# Throws     : Croaks on invalid invocation and invalid args
# Notes      : Perl, by default, will consider accented letters as having a
#              length of two. This function uses a very common algorythm
#              recommended all over the internet, including in the Perl Unicode
#              cookbook: http://search.cpan.org/~shay/perl-5.20.2/pod/perlunicook.pod
#              Before resorting to this technique, I tried to use the
#              grapheme_length function from Unicode::Util, but it proved
#              unacceptably slow.
# See Also   :
sub _grapheme_length{
    my $class = shift;
    my $string = shift;
    
    # validate args
    _force_class($class);
    unless(defined $string && ref $string eq q{}){
        $_CLASS->_error('invalid args, must pass a scalar');
    }
    
    # do the calculation
    my $grapheme_length = 0;
    while($string =~ /\X/gsx){$grapheme_length++};
    
    # return the result
    return $grapheme_length;
}

1; # because Perl is just a little bit odd :)
__END__

#==============================================================================
# User Documentation
#==============================================================================

=head1 NAME

C<Crypt::HSXKPasswd> - A secure memorable password generator inspired by Steve
Gibson's Passord Haystacks (L<https://www.grc.com/haystack.htm>), and the
famous XKCD password cartoon (L<https://xkcd.com/936/>).

=head1 VERSION

This documentation refers to C<Crypt::HSXKPasswd> version 3.1.1.

=head1 SYNOPSIS

    use Crypt::HSXKPasswd;

    #
    # Functional Interface - a shortcut for generating single passwords
    #
    
    # generate a single password using the default word source, configuration,
    # and random number generator
    my $password = hsxkpasswd();
    
    # the above call is simply a shortcut for the following
    my $password = Crypt::HSXKPasswd->new()->password();
    
    # this function passes all arguments on to Crypt::HSXKPasswd->new()
    # so all the same customisations can be specified, e.g. specifying a
    # config preset:
    my $password = hsxkpasswd(preset => 'XKCD');
    
    #
    # Object Oriented Interface - recommended for generating multiple passwords
    #
    
    # create a new instance with the default dictionary, config, and random
    # number generator
    my $hsxkpasswd_instance = Crypt::HSXKPasswd->new();
    
    # generate a single password
    my $password = $hsxkpasswd_instance->password();
    
    # generate multiple passwords
    my @passwords = $hsxkpasswd_instance->passwords(10);

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

=head3 The Entropy of HSXKPasswd Passwords

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
    
Finally, we convert this to entropy by taking the base 2 log:

    Eseen = Log(2)2.77x10^17 = ~57bits
    
What this means is that most probably, passwords generated with this preset
using the sample dictionary file are spectacularly more secure than even
12 randomly chosen characters, and, that in the very unlikely event that an
attackers knows absolutely everything about how the password was generated,
it is still significantly more secure than 8 randomly chosen characters.

Because the exact strength of the passwords produced by this module depend on
the configuration and dictionary file used, the constructor does the above
math when creating an HSXKPasswd object, and throws a warning if either the
blind entropy falls below 78bits, or the seen entropy falls below 52 bits.

=head1 SUBROUTINES/METHODS

=head2 WORD SOURCES (DICTIONARIES)

The abstract class C<Crypt::HSXKPasswd::Dictionary> acts as a base class for
sources of words for use by this module. Word sources should extend this base
class and implement the function C<word_list()>, which should return an array
of words.

In order to produce secure passwords it's important to use a word source that
contains a large selection of words with a good mix of different lengths of
words.

The module ships with a number of pre-defined word sources:

=head3 C<Crypt::HSXKPasswd::Dictionary::DE>

A German word list based on the GPL-licensed German dictionary for WinEdit by
Juergen Vierheilig.

B<Note:> This module is licensed under the GPL, not the BSD license used for the 
majority of this project.

=head3 C<Crypt::HSXKPasswd::Dictionary::EN_Default>

A default word list consisting of English words and place names.

=head3 C<Crypt::HSXKPasswd::Dictionary::ES>

A Spanish word list based on the BSD-licensed Spanish dictionary for WinEdit by
Juan L. Varona from the Universidad de La Rioja.

=head3 C<Crypt::HSXKPasswd::Dictionary::FR>

A French word list based on the GPL-licensed French dictionary for WinEdit.

B<Note:> This module is licensed under GPL V2, not the BSD license used for the 
majority of this project.

=head3 C<Crypt::HSXKPasswd::Dictionary::IT>

An Italian word list based on the free-for-non-commerical-use Italian dictionary
for WinEdit by Karl Koeller.

B<Note:> This module is licensed under GPL V2, not the BSD license used for the 
majority of this project.

=head3 C<Crypt::HSXKPasswd::Dictionary::NL>

A Dutch/Flemish word list based on the GPL-licensed Dutch dictionary for WinEdit.

B<Note:> This module is licensed under GPL V2, not the BSD license used for the 
majority of this project.

=head3 C<Crypt::HSXKPasswd::Dictionary::PT>

A Portuguese word list based on the GPL-licensed Portuguese dictionary for
WinEdit compiled by Bernhard Enders (building on work by Raimundo Santos Moura &
Ricardo Ueda Karpischek).

B<Note:> This module is licensed under GPL V2.1, not the BSD license used for
the majority of this project.

=head3 C<Crypt::HSXKPasswd::Dictionary::System>

This class tries to find and use a Unix words file on the system.

The constructor croaks if no system words file can be found.

=head4 Usage

    my $word_source = Crypt::HSXKPasswd::Dictionary::System->new();

=head3 C<Crypt::HSXKPasswd::Dictionary::Basic>

This class can be initialised from a words file, or from an array ref
containing words.

=head4 Usage

    my $word_source = Crypt::HSXKPasswd::Dictionary::Basic->new('file_path');
    my $word_source = Crypt::HSXKPasswd::Dictionary::Basic->new(
        'file_path',
        'Latin1'
    );
    my $word_source = Crypt::HSXKPasswd::Dictionary::Basic->new($array_ref);


The rules for the formatting of dictionary files are simple. Dictionary
files must contain one word per line. Words shorter than four letters will be
ignored, as will all lines starting with the # symbol. Files are assumed to be
UTF-8 encoded, but an optional second argument can be passed specifying a
different file encoding.

This format is the same as that of the standard Unix Words file, usually found
at C</usr/share/dict/words> on Unix and Linux operating systems (including OS
X).

=head2 CONFIGURATION

The module builds passwords using the following process.

First, a set of words are randomly chosen from the word source. Then, two
pseudo-words made of one or more digits may added before and/or after the words
from. Next, a separator character may be placed between all the words
(including the groups of digits), and one or more occurrences of a padding
symbol may be added front and/or back.

You can envisage the process as follows:

    correct HORSE BATTERY staple
    34 correct HORSE BATTERY staple 56
    34-correct-HORSE-BATTERY-staple-56
    !!34-correct-HORSE-BATTERY-staple-56!!
    
Many aspects of this password generation process are configurable. You can
control the length and number of words chosen, and what, if any, case
transformations should be applied to those words, and how accented characters
should be treated. How many, if any, digits should be added front and back.
What symbol, if any, should be used as a separator. And finally how the
password should be padded, if at all, and with what symbol. Passwords can be
padded to a given length, or by a given number of symbols front and back.

The symbols used as the separator and for padding can be explicitly specified,
or the they can be randomly chosen from a given alphabet of possible symbols.
Both symbols can be randomly chosen from the same alphabet, or from two
separately specified alphabets.

Every instance of an HSXKPasswd password generator stores its configuration as
a set of name-value pairs, referred to as I<configuration keys> throughout this
documentation.

Configurations can be specified either as a complete set of configuration keys
with values that together form a valid configuration, as a named preset, or, as
a named preset accompanied by a list of one or more configuration keys
with new values to override those specified by the preset.

The module contains a preset called C<DEFAULT>, and this preset is used if no
configuration is specified. The function C<default_config()> will return a copy
of this configuration as a reference to a hashtable.

For more details on how to specify configurations, see the documentation for
the constructor (the function C<new()>) below.

=head3 CONFIGURATION KEYS

Below is a list of all supported Keys, a description of what aspect of the
configuration they control, and the validation rules that apply.

Note that some keys are always required, and that there are dependencies
across keys. For examples, if you specify that the separator symbol should be
chosen at random, you must also specify an alphabet from which to chose the
character.

=over 4

=item *

C<allow_accents> (optional) - if not specified, or if a falsy value is
specified, accents will be removed from letters in the generated passwords.
E.g. C<E<eacute>> becomes C<e>. If a truthy value is specified, accents will
be preserved, and appear in the generated passwords.

=item *

C<case_transform> (required) - the transformations, if any, that should be
applied to the words that appear in the generated passwords. The value specified
must be one of the following:

=over 4

=item *

C<ALTERNATE> - each alternate word will be converted to all upper case and
all lower case.

=item *

C<CAPITALISE> - the first letter in every word will be converted to upper case,
all other letters will be converted to lower case.

=item *

C<INVERT> - the first letter in every word will be converted to lower case,
all other letters will be converted to upper case.

=item *

C<LOWER> - all letters in all the words will be converted to lower case. B<Use
of this option is strongly discouraged for security reasons.>

=item *

C<NONE> - the case of the letters that make up the words will not be altered
from how they were specified in the original word source.

=item *

C<RANDOM> - each word will be randomly converted to all upper case or all lower
case.

=item *

C<UPPER> - all letters in all the words will be converted to upper case. B<Use
of this option is strongly discouraged for security reasons.>

=back

The function C<default_config()> returns a value of C<CAPITALISE> for this key.

=item *

C<character_substitutions> (optional) - a reference to a hashtable containing
containing zero or more character substitutions to be applied to the randomly
chosen words when generating passwords. The keys in the hashtable must be
single letters. The substitutions can contain multiple characters. Specifying
one or more substitutions with a length greater than one could lead to
passwords being longer than expected, and to entropy calculations being under
estimated. The module will issue a warning when such a config is loaded.

=item *

C<num_words> (required) - the number of words to randomly choose from the word
source as the basis for the generated passwords.

The function C<default_config()> returns a value of C<3> for this key.

=item *

C<pad_to_length> (conditionally required) - the length generated passwords must
be padded to when using adaptive padding, i.e. when C<padding_type> is set to
C<ADAPTIVE>). The value must be an integer greater than or equal to 12. Lengths
of less than 12 are not permitted for security reasons.

=item *

C<padding_alphabet> (optional) - this key is ignored unless the configuration
specifies that the padding character should be randomly chosen, i.e. unless
C<padding_character> is set to C<RANDOM>.

When the padding character is set to be randomly chosen, the module will check
for the presence of this key. If it is specified, the padding character will
be randomly chosen from the set of symbols defined by this key. If this key is
not set, the module will use the set of symbols specified by the key
C<symbol_alphabet>. If neither this key nor C<symbol_alphabet> are specified,
then the configuration will be considered invalid.

If specified, this key must be a reference to an array of single-character
strings.

=item *

C<padding_character> (conditionally required) - this key is unless the key
C<padding_type> is set to C<NONE>. It specifies the padding symbol to be used
when generating passwords.

If specified, they key's value must be a single character string, or one of the
following special values:

=over 4

=item *

C<RANDOM> - the character should be randomly chosen from the set of characters
specified by the key C<padding_alphabet> or C<symbol_alphabet>. If specified,
C<padding_alphabet> takes precedence over C<symbol_alphabet>. If this value
is specified for C<padding_character>, and neither C<padding_alphabet> nor
C<symbol_alphabet> are specified, the configuration will be considered invalid.

=item *

C<SEPARATOR> - pad the password with the same symbol that is used to separate
the words. The key C<padding_character> cannot be set to C<SEPARATOR> when the
key C<separator_character> is set to C<NONE>.


=back


The function C<default_config> return the value C<RANDOM> for this key.

=item *

C<padding_characters_before> & C<padding_characters_after> (conditionally
required) - both of these keys are required if the key C<padding_type> is set
to C<FIXED>.

These keys specify the number of padding symbols that should be added to the
front and back of the password.

Both keys require that the specified value be an integer greater than or equal
to zero.

The function C<default_config()> returns a value of C<2> for both of these
keys.

=item *

C<padding_digits_before> & C<padding_digits_after> (required) - the number of
random digits to include before and after the randomly chosen words when
generating passwords.

Both keys require that the specified value be an integer greater than or equal
to zero.

The function C<default_config()> returns a value of C<2> for both of these
keys.

=item *

C<padding_type> (required) - the way in which padding symbols should be added
when generating passwords.

Only the following values are valid for this key:

=over 4

=item *

C<NONE> - do not add any padding symbols when generating passwords.

=item *

C<FIXED> - add an exactly specified number of copies of the padding symbol to
the front and back of generated passwords.

When they key C<padding_type> is set to C<FIXED>, the three keys
C<padding_character>, C<padding_characters_before> &
C<padding_characters_after> become required.

=item *

C<ADAPTIVE> - add no copies of the padding symbol will be added to the front
of the generated passwords, and copies of the padding character will be added
to the end of the generated passwords until the total length of the password is
equal to the value specified for the key C<pad_to_length>.

Note that If the password is longer than the value specified by the key
C<pad_to_length> before any copies of the padding symbol are added, the
password will be truncated to the length specified by the key C<pad_to_length>.

When they key C<padding_type> is set to C<ADAPTIVE>, the three keys
C<padding_character>, C<padding_characters_before> &
C<padding_characters_after> become required.

=back

The function C<default_config()> returns a value of C<FIXED> for this key.

=item *

C<separator_alphabet> (optional) - this key is ignored unless the configuration
specifies that the separator character should be randomly chosen, i.e. unless
C<separator_character> is set to C<RANDOM>.

When the separator character is set to be randomly chosen, the module will
check for the presence of this key. If it is specified, the separator character
will be randomly chosen from the set of symbols defined by this key. If this
key is not set, the module will use the set of symbols specified by the key
C<symbol_alphabet>. If neither this key nor C<symbol_alphabet> are specified,
then the configuration will be considered invalid.

If specified, this key must be a reference to an array of single-character
strings.

=item *

C<separator_character> (required) - the symbol to use to separate the words
when generating passwords.

The value specified for this key must be a single-character string, or one of
the following special values:

=over 4

=item *

C<NONE> - no separator character will be used. I.e. the words, and the groups
of digits before and after the words, if any, will be directly joined together.

C<RANDOM> - a single character will be randomly chosen from the list of symbols
specified by one of the keys C<separator_alphabet> or C<symbol_alphabet>. If
both keys are set, C<separator_alphabet> takes precedence.

=back

The function C<default_config()> returns a value of C<RANDOM> for this key.

=item *

C<symbol_alphabet> (optional) - this key specifies a default alphabet of
symbols that can be used when either or both the separator character and the
padding character are set to be chosen at random. I.e. when either or both of
the keys C<separator_character> and C<padding_character> are set to C<RANDOM>.

Note that the keys C<separator_alphabet> and C<padding_alphabet> take
precedence over this key if specified.

The value specified for this key must be a reference to an array of
single-character strings.

The function C<default_config()> returns a value of
C<['!', '@', '$', '%', '^', '&', '*', '-', '_',
'+', '=', ':', '|', '~', '?', '/', '.', ';']>
for this key.

=item *

C<word_length_min> & C<word_length_max> (required) - the minimum and maximum
length of the words that will form the basis of the generated passwords.

The values specified for both keys must be integers greater than three, and
the value specified for C<word_length_max> must be greater than or equal to
the value specified for C<word_length_min>.

The function C<default_config()> returns values of C<4> and C<8> for these keys.

=back

=head2 PRESETS

Below is a list of all the presets defined by this module.

This information can be accessed programatically using the functions
C<defined_presets()>, C<presets_to_string()>, C<preset_description()>, and
C<preset_config()>.

=over 4

=item *

C<APPLEID> - a preset respecting the many prerequisites Apple places on Apple
ID passwords. Apple's official password policy cam be found at the following
URL: L<http://support.apple.com/kb/ht4232>. Note that Apple's knowledge base
article omits to mention that passwords can't be longer than 32 characters.
This preset is also configured to use only characters that are easy to type on
the standard iOS keyboard, i.e. those appearing on the letters keyboard
(C<ABC>) or the numbers keyboard C<.?123>, and not those on the harder to reach
symbols keyboard C<#+=>. 

Sample Password:

    @60:london:TAUGHT:forget:70@
    
Preset Definition:

    {
        padding_alphabet => [qw{! ? @ &}],
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
        allow_accents => 0,
    }

=item *

C<DEFAULT> - the default configuration. 

Sample Password:

    ~~12:settle:SUCCEED:summer:48~~
    
Preset Definition:

    {
        symbol_alphabet => [qw{! @ $ % ^ & * - _ + = : | ~ ? / . ;}],
        word_length_min => 4,
        word_length_max => 8,
        num_words => 3,
        separator_character => 'RANDOM',
        padding_digits_before => 2,
        padding_digits_after => 2,
        padding_type => 'FIXED',
        padding_character => 'RANDOM',
        padding_characters_before => 2,
        padding_characters_after => 2,
        case_transform => 'ALTERNATE',
        allow_accents => 0,
    }

=item *

C<NTLM> - a preset for 14 character NTMLv1 (NTLM Version 1) passwords. B<ONLY
USE THIS PRESET IF YOU MUST!> The 14 character limit does not allow for
sufficient entropy in scenarios where the attacker knows the dictionary and
config used to generate the password. Use of this preset will generate a low
entropy warning.

Sample Password:

    0=mAYAN=sCART@
    
Preset Definition:

    {
        padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
        allow_accents => 0,
    }

=item *

C<SECURITYQ> - a preset for creating fake answers to security questions. This
preset generates long nonsense sentences ending in C<.> C<!> or C<?>.

Sample 'Password':

    Wales outside full month minutes gentle?
    
Preset Definition:

    {
        word_length_min => 4,
        word_length_max => 8,
        num_words => 6,
        separator_character => q{ },
        padding_digits_before => 0,
        padding_digits_after => 0,
        padding_type => 'FIXED',
        padding_character => 'RANDOM',
        padding_alphabet => [qw{. ! ?}],
        padding_characters_before => 0,
        padding_characters_after => 1,
        case_transform => 'NONE',
        allow_accents => 0,
    }

=item *

C<WEB16> - a preset for websites that don't allow passwords to be longer than
16 characters. Because 16 characters is not very long, a large symbol alphabet
had to be used to provide sufficient entropy.

Sample Password:

    :baby.ohio.DEAR:
    
Preset Definition:

    {
        padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
        allow_accents => 0,
    }
    
=item *

C<WEB32> - a preset for websites that don't allow passwords to be longer than
32 characters.

Sample Password:

    +93-took-CASE-money-AHEAD-31+
    
Preset Definition:

    {
        padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
        allow_accents => 0,
    }

=item *

C<WIFI> - a preset for generating 63 character long WPA2 keys (most routers
allow 64 characters, but some only allow 63, hence the somewhat unexpected
length).

Sample Password:

    2736_ITSELF_PARTIAL_QUICKLY_SCOTLAND_wild_people_7441!!!!!!!!!!
    
Preset Definition:

    {
        padding_alphabet => [qw{! @ $ % ^ & * + = : | ~ ?}],
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
        allow_accents => 0,
    }

=item *

C<XKCD> - a preset inspired by the original XKCD comic
(L<http://xkcd.com/936/>), but with some alterations to provide sufficient
entropy to avoid low entropy warnings.

Sample Password:

    KING-madrid-exercise-BELGIUM
    
Preset Definition:

    {
        word_length_min => 4,
        word_length_max => 8,
        num_words => 4,
        separator_character => q{-},
        padding_digits_before => 0,
        padding_digits_after => 0,
        padding_type => 'NONE',
        case_transform => 'RANDOM',
        allow_accents => 0,
    }

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

C<$Crypt::HSXKPasswd::ENTROPY_MIN_BLIND> - the minimum acceptable entropy (in
bits) for a brute-force attack. The default value for this variable is 78
(equivalent to a 12 character password consisting of mixed-case letters, digits,
and symbols).

=item *

C<$Crypt::HSXKPasswd::ENTROPY_MIN_SEEN> - the minimum acceptable entropy (in
bits) for a worst-case attack (where the dictionary and configuration are
known). The default value for this variable is 52 (equivalent to an 8 character
password consisting of mixed-case letters, digits, and symbols).

=item *

C<$Crypt::HSXKPasswd::SUPRESS_ENTROPY_WARNINGS> - this variable can be used to
suppress one or both of the entropy warnings. The following values are valid
(invalid values are treated as being C<NONE>):

=over 4

=item -

C<NONE> - no warnings are suppressed. This is the default value.

=item -

C<SEEN> - only warnings for the worst-case scenario are suppressed.

=item -

C<BLIND> - only warnings for the best-case scenario are suppressed.

=item -

C<ALL> - all entropy warnings are suppressed.

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

=head2 RANDOM NUMBER SOURCES

In order to minimise the number of non-standard modules this module requires,
the default source of randomness is Perl's built-in C<rand()> function. This
provides a reasonable level of randomness, and should suffice for most users,
however, some users will prefer to make use of one of the many advanced
randomisation modules in CPAN, or, reach out to a web service like
L<http://random.org> for their random numbers. To facilitate both of these
options, this module uses a cache of randomness, and provides an abstract
Random Number Generator (RNG) class that can be extended.

The module can use an instance of any class that extends
C<Crypt::HSXKPasswd::RNG> as it's source of randomness. Custom RNG classes
must implement the method C<random_numbers()> which will be invoked on an
instance of the class and passed one argument, the number of random numbers
required to generate a single password. The function must return an array
of random numbers between 0 and 1. The number of random numbers returned is
entirely up to the module to decide. The number required for a single password
is passed purely as a guide. The function must always return at least one
random number.

The module ships with five standard RNGs (described below).

By default, the module will try to use one of the following four RNGs, listed
from most to least preferred, depending on what is available on the system:

=over 4

=item 1

C<Crypt::HSXKPasswd::RNG::Math_Random_Secure> (only available if
C<Math::Random::Secure> is installed on the system).

=item 2

C<Crypt::HSXKPasswd::RNG::Data_Entropy> (only available if
C<Data::Entropy::Algorithms> is installed on the system).

=item 3

C<Crypt::HSXKPasswd::RNG::DevUrandom> (only available on Linux/Unix systems
with a C</dev/urandom>).

=item 4

C<Crypt::HSXKPasswd::RNG::Basic> (available on all systems because it uses
Perl's built-in C<rand()> function).

=back

If the constructor is called without specifying an RNG, and if the only
available RNG is C<Crypt::HSXKPasswd::RNG::Basic>, a warning will be thrown
suggesting installing C<Math::Random::Secure> or C<Data::Entropy::Algorithms>.

The module also ships with a fifth RNG, C<Crypt::HSXKPasswd::RNG::RandomDotOrg>,
but this one must be explicitly used, the constructor will never used it by
default. As its name suggests, this class uses L<http://Random.Org/>'s HTTP API
to generate random numbers.

To explicitly use any particular RNG, create an instance of it, and either pass
that instance to the constructor with the named argument C<rng>, or, set the RNG
after instantiating the object using the C<rng()> function.

=head3 Crypt::HSXKPasswd::RNG::Math_Random_Secure

    my $rng = Crypt::HSXKPasswd::RNG::Math_Random_Secure->new();

This is the preferred RNG because it is both fast and secure, but, it requires
the non-standard module C<Math::Random::Secure>
(L<http://search.cpan.org/perldoc?Math%3A%3ARandom%3A%3ASecure>) be installed.

=head3 Crypt::HSXKPasswd::RNG::Data_Entropy

    my $rng = Crypt::HSXKPasswd::RNG::Data_Entropy->new();

This RNG is secure, but it is quite slow (about six times slower than
C<Crypt::HSXKPasswd::RNG::Math_Random_Secure>), and it requires
the non-standard module C<Data::Entropy::Algorithms>
(L<http://search.cpan.org/perldoc?Data%3A%3AEntropy%3A%3AAlgorithms>) be
installed.

=head3 Crypt::HSXKPasswd::RNG::DevUrandom

    my $rng = Crypt::HSXKPasswd::RNG::DevUrandom->new();
    
This RNG is secure and relatively fast (faster than
C<Crypt::HSXKPasswd::RNG::Data_Entropy> but slower than
C<Crypt::HSXKPasswd::RNG::Math_Random_Secure>), but is only available on
Linux/Unix systems with a C</dev/urandom> special file.

=head3 Crypt::HSXKPasswd::RNG::Basic

    my $rng = Crypt::HSXKPasswd::RNG::Basic->new();
    
This RNG uses Perl's built-in C<rand()> function as its source of randomness,
and this is sub-optimal. The Perl docs warn that C<rand()> is not a particularly
good source of random numbers, and advises against its use for cryptography.

This RNG provides a base-line, and should only be used if none of the better
RNGs are available. While it is sub-optimal, it will still generate passwords
with sufficient entropy in most situations. Ultimately, even using this
imperfect RNG, this module will still produce passwords that are much better
than those produced by the human imagination!

=head3 Crypt::HSXKPasswd::RNG::RandomDotOrg

    my $rng = Crypt::HSXKPasswd::RNG::RandomDotOrg->new('my.address@my.dom');
    my $rng = Crypt::HSXKPasswd::RNG::RandomDotOrg->new('my.address@my.dom',
        timeout => 180,
        num_passwords => 3,
    );

This RNG serves as a usable example of an RNG that queries a web service. As its
name suggests, this class uses L<http://Random.Org/>'s HTTP API to generate
random numbers.

In order to comply with Random.Org's client guidelines
(L<https://www.random.org/clients/>), this module requires that a valid email
address be passed as the first argument.

The client guidelines also request that clients use long timeouts, and batch
their requests. They prefer to be asked for more number less frequently than
less numbers more frequently. For this reason the class's default behaviour is
to use a timeout of 180 seconds, and to request enough random numbers to
generate three passwords at a time.

These defaults can be overridden by passing named arguments to the constructor
after the email address. The following named arguments are supported:

=over 4

=item *

C<timeout> - the timeout to use when making HTTP requests to Random.Org in
seconds (the default is 180).

=item *

C<num_passwords> - the number of password generations to fetch random numbers
for per request from Random.org. This value is in effect a multiplier for the
value passed to the C<random_numbers()> function by C<Crypt::HSXKPasswd>.

C<num_absolute> - the absolute number of random numbers to fetch per request
to Random.Org. This argument takes precedence over C<num_passwords>.

=back

C<num_passwords> and C<num_absolute> should not be used together, but if they
are, C<num_absolute> use used, and C<num_passwords> is ignored.

This class  requires a number of modules not used by any other classes under
C<Crypt::HSXKPasswd>, and not listed in that module's requirements. If all of
the following modules are not installed, the constructor will croak:

=over 4

=item *

C<Email::Valid>

=item *

C<LWP::UserAgent>

=item *

C<Mozilla::CA>

=item *

C<URI>

=back

=head2 FUNCTIONAL INTERFACE

Although the package was primarily designed to be used in an object-oriented
way, there is a functional interface too. The functional interface initialises
an object internally and then uses that object to generate a single password.
If you only need one password, this is no less efficient than the
object-oriented interface, however, if you are generating multiple passwords it
is much less efficient.

There is only a single function exported by the module:

=head3 hsxkpasswd()

    my $password = hsxkpasswd();
    
This function call is equivalent to the following Object-Oriented code:

    my $password =  HSXKPasswd->new()->password();
    
This function passes all arguments it receives through to the constructor, so all
arguments that are valid in C<new()> are valid here.

This function Croaks if there is a problem generating the password.

Note that it is inefficient to use this function to generate multiple passwords
because the dictionary will be re-loaded, and the entropy stats re-calculated
each time the function is called.

=head2 CONSTRUCTOR
    
    # create a new instance with the default dictionary, config, and random
    # number generator
    my $hsxkpasswd_instance = Crypt::HSXKPasswd->new();
    
    # the constructor takes optional named arguments, these can be used to
    # customise the word source, config, and random number source.
    
    # create an instance that uses the UNIX words file as the word source
    my $hsxkpasswd_instance = HSXKPasswd->new(
        dictionary => Crypt::HSXKPasswd::Dictionary::System->new()
    );
    
    # create an instance that uses an array reference as the word source
    my $hsxkpasswd_instance = HSXKPasswd->new(dictionary_list => $array_ref);
    
    # create an instance that uses a dictionary file as the word source
    my $hsxkpasswd_instance = HSXKPasswd->new(
        dictionary_file => 'sample_dict_EN.txt'
    );
    
    # the class Crypt::HSXKPasswd::Dictionary::Basic can be used to aggregate
    # multiple array refs and/or dictionary files into a single word source
    my $dictionary = Crypt::HSXKPasswd::Dictionary::Basic->new();
    $dictionary->add_words('dict1.txt');
    $dictionary->add_words('dict2.txt');
    $dictionary->add_words($array_ref);
    my $hsxkpasswd_instance = HSXKPasswd->new(dictionary => $dictionary);
    
    # create an instance from the preset 'XKCD'
    my $hsxkpasswd_instance = HSXKPasswd->new(preset => 'XKCD');
    
    # create an instance based on the preset 'XKCD' with one customisation
    my $hsxkpasswd_instance = HSXKPasswd->new(
        preset => 'XKCD',
        preset_override => {separator_character => q{ }}
    );
    
    # create an instance from a config based on a preset
    # but with many alterations
    my $config = HSXKPasswd->preset_config('XKCD');
    $config->{separator_character} = q{ };
    $config->{case_transform} = 'INVERT';
    $config->{padding_type} = "FIXED";
    $config->{padding_characters_before} = 1;
    $config->{padding_characters_after} = 1;
    $config->{padding_character} = '*';
    my $hsxkpasswd_instance = HSXKPasswd->new(config => $config);
    
    # create an instance from an entirely custom configuration
    my $config = {
        padding_alphabet => [qw{! @ $ % ^ & * + = : ~ ?}],
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
    }
    my $hsxkpasswd_instance = HSXKPasswd->new(config => $config);
    
    # create an instance from an entire custom config passed as a JSON string
    # a convenient way to use configs generated using the web interface at
    # https://xkpasswd.net
    my $config = <<'END_CONF';
    {
     "num_words": 4,
     "word_length_min": 4,
     "word_length_max": 8,
     "case_transform": "RANDOM",
     "separator_character": " ",
     "padding_digits_before": 0,
     "padding_digits_after": 0,
     "padding_type": "NONE",
    }
    END_CONF
    my $hsxkpasswd_instance = HSXKPasswd->new(config_json => $config);
    
    # create an instance which uses /dev/urandom as the RNG
    # (only possible on Linux/Unix only systems)
    my $hsxkpasswd_instance = HSXKPasswd->new(
        rng => Crypt::HSXKPasswd::RNG::DevUrandom->new();
    );
    
    # create an instance which uses Random.Org as the random number generator
    # NOTE - this should be used sparingly, and only by the paranoid. If you
    # abuse this RNG your IP will get blacklisted on Random.Org. You must pass
    # a valid email address to the constructor for
    # Crypt::HSXKPasswd::RNG::RandomDorOrg because Random.Org's usage
    # guidelines request that all invocations to their API contain a contact
    # email in the useragent header, and this module honours that request.
    my $hsxkpasswd_instance = HSXKPasswd->new(
        rng => Crypt::HSXKPasswd::RNG::RandomDorOrg->new('your.email@addre.ss');
    );

The constructor must be called via the package name.

If called with no arguments the constructor will use an instance of
C<Crypt::HSXKPasswd::Dictionary::EN_Default> as the word source, the preset
C<DEFAULT>, and an instance of the class C<Crypt::HSXKPasswd::RNG::Basic> to
generate random numbers.

The function accepts named arguments to allow for custom specification of the
word source, config, and random number source.

=head3 CUSTOM WORD SOURCES IN CONSTRUCTOR

Three named arguments can be used to specify a word source, but only one should
be specified at a time. If multiple are specified, the one with the highest
priority will be used, and the rest ignored. The variables are listd below in
descending order of priority:

=over 4

=item *

C<dictionary> - an instance of a class that extends
C<Crypt::HSXKPasswd::Dictionary>.

=item *

C<dictionary_list> - a reference to an array containing words as scalars.

=item *

C<dictionary_file> - the path to a dictionary file. Dictionary files should
contain one word per. Lines starting with a # symbol will be ignored. It is
assumed files will be UTF-8 encoded. If not, a second named argument,
C<dictionary_file_encoding>, can be used to specify another encoding.

=back

=head3 CUSTOM CONFIGS

Two primary named arguments can be used to specify the config the instance
should use to generate passwords. Only one should be specified at a time. If
multiple are specified, the one with the highest priority will be used, and the
rest ignored. The variables are listd below in descending order of priority:

=over 4

=item *

C<config> - a valid config hashref.

=item *

C<config_json> - a JSON string representing a valid config hashref. If you use
this named argument on a system where the standard Perl JSON library
L<http://search.cpan.org/perldoc?JSON> is not installed, the constructor will
croak.

This named argument provides a convenient way to use configs generated using
the web interface at L<https://xkpasswd.net/>. The Save/Load tab in that
interface saves and loads configs in JSON format.

=item *

C<preset> - a valid preset name. If this variable is used, then any desired
config overrides can be passed as a hashref using the variable
C<preset_overrides>.

=back

=head3 CUSTOM RANDOM NUMBER GENERATORS

A custom RNG can be specified using the named argument C<rng>. The passed value
must be an instance of a class that extends C<Crypt::HSXKPasswd::RNG> and
overrides the function C<random_numbers()>.

=head2 CLASS METHODS

B<NOTE> - All class methods must be invoked via the package name, or they will
croak.

=head3 clone_config()

    my $clone = Crypt::HSXKPasswd->clone_config($config);
    
This function must be passed a valid config hashref as the first argument or it
will croak. The function returns a hashref.

=head3 config_key_definition()

    my %key_definition = Crypt::HSXKPasswd->config_key_definition($key_name);
    
A function to return the definition for a config key. The definition is returned
as a hash indexed by the following keys:

=over 4

=item *

C<required> - 1 if the key is a required key, and 0 otherwise.

=item *

C<type> - a C<Type::Tiny> object representing the valid data type for the key.

=item *

C<type_description> - an English description of valid values for the key.

=back

=head3 config_key_definitions()

    my %key_definitions = Crypt::HSXKPasswd->config_key_definitions();
    
A function to return definitions for all defined config keys as a hash indexed
by config key names. Each definition is represented as a hash with the same keys
as the hashes returned by the function C<config_key_definition()>.

=head3 config_stats()

    my %stats = Crypt::HSXKPasswd->config_stats($config);
    
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

=head3 config_to_json()

    my $config_json_string = Crypt::HSXKPasswd->config_to_json($config);
    
This function returns a JSON representation of the passed config hashref as a
scalar string.

The function must be passed a valid config hashref or it will
croak. This function will also croak if called without the standard JSON Perl
module (L<http://search.cpan.org/perldoc?JSON>) installed.

=head3 config_to_string()

    my $config_string = Crypt::HSXKPasswd->config_to_string($config);
    
This function returns the content of the passed config hashref as a scalar
string. The function must be passed a valid config hashref or it will croak.

=head3 default_config()

    my $config = Crypt::HSXKPasswd->default_config();

This function returns a hashref containing a config with default values.

This function can optionally be called with a single argument, a hashref
containing keys with values to override the defaults with.

    my $config = Crypt::HSXKPasswd->default_config({num_words => 3});
    
When overrides are present, the function will carp if an invalid key or value
is passed, and croak if the resulting merged config is invalid.

This function is a shortcut for C<preset_config()>, and the two examples above
are equivalent to the following:

    my $config = Crypt::HSXKPasswd->preset_config('DEFAULT');
    my $config = Crypt::HSXKPasswd->preset_config('DEFAULT', {num_words => 3});

=head3 defined_config_keys()

    my @config_key_names = Crypt::HSXKPasswd->defined_config_keys();
    
This function returns the list of valid config key names as an array of strings.

=head3 defined_presets()

    my @preset_names = Crypt::HSXKPasswd->defined_presets();
    
This function returns the list of defined preset names as an array of strings.

=head3 is_valid_config()

    my $is_ok = Crypt::HSXKPasswd->is_valid_config($config);
    
This function must be passed a hashref to test as the first argument or it will
croak. The function returns 1 if the passed config is valid, and 0 otherwise.

Optionally, any truthy value can be passed as a second argument to indicate
that the function should croak on invalid configs rather than returning 0;

    use English qw( -no_match_vars );
    eval{
        Crypt::HSXKPasswd->is_valid_config($config, 'do_croak');
    }or do{
        print "ERROR - config is invalid because: $EVAL_ERROR\n";
    }

=head3 preset_config()

    my $config = Crypt::HSXKPasswd->preset_config('XKCD');
    
This function returns the config hashref for a given preset. See above for the
list of available presets.

The first argument this function accepts is the name of the desired preset as a
scalar. If an invalid name is passed, the function will carp. If no preset is
passed the preset C<DEFAULT> is assumed.

This function can optionally accept a second argument, a hashref
containing keys with values to override the defaults with.

    my $config = Crypt::HSXKPasswd->preset_config(
        'XKCD',
        {case_transform => 'INVERT'}
    );
    
When overrides are present, the function will carp if an invalid key or value is
passed, and croak if the resulting merged config is invalid.

=head3 presets_json()

    my $json_string = Crypt::HSXKPasswd->presets_json();
    
This function returns a JSON string representing all the defined configs,
including their descriptions.

The returned JSON string represents a hashref indexed by three keys:
C<defined_keys> contains an array of preset identifiers, C<presets> contains the
preset configs indexed by reset identifier, and C<preset_descriptions> contains
a hashref of descriptions indexed by preset identifiers.

This function requires that the standard Perl JSON module be installed, if not,
it will croak.

=head3 preset_description()

    my $description = Crypt::HSXKPasswd->preset_description('XKCD');
    
This function returns the description for a given preset. See above for the
list of available presets.

The first argument this function accepts is the name of the desired preset as a
scalar. If an invalid name is passed, the function will carp. If no preset is
passed the preset C<DEFAULT> is assumed.

=head3 presets_to_string()

    print Crypt::HSXKPasswd->presets_to_string();
    
This function returns a string containing a description of each defined preset
and the configs associated with the presets.

=head2 METHODS

B<NOTE> - all methods must be invoked on an XKPasswd object or they will croak.

=head3 config()

    my $config = $hsxkpasswd_instance->config(); # getter
    $hsxkpasswd_instance->config($config_hashref); # setter
    $hsxkpasswd_instance->config($config_json_string); # setter

When called with no arguments the function returns a clone of the instance's
config hashref.

When called with a single argument the function sets the config of the instance
to a clone of the passed config. If present, the argument must be either a
hashref containing valid config keys and values, or a JSON string representing
a hashref containing valid config keys and values.

The function will croak if an invalid config is passed, or, if a string is
passed while the standard JSON Perl module
(L<http://search.cpan.org/perldoc?JSON>) is not installed.

=head3 config_json()

    my $config_json_string = $hsxkpasswd_instance->config_json();
    
This function returns the content of the instance's loaded config hashref as a
JSON string.

The output from this function can be loaded into the web interface at
L<https://xkpasswd.net> (using the load/save tab).

The function will croak if the standard JSON Perl module
(L<http://search.cpan.org/perldoc?JSON>) is not installed.

=head3 config_string()

    my $config_string = $hsxkpasswd_instance->config_string();
    
This function returns the content of the instance's loaded config hashref as a
scalar string.

=head3 dictionary()

    my $dictionary_clone = $hsxkpasswd_instance->dictionary();
    $hsxkpasswd_instance->dictionary($dictionary_instance);
    $hsxkpasswd_instance->dictionary($array_ref);
    $hsxkpasswd_instance->dictionary('sample_dict_EN.txt');
    $hsxkpasswd_instance->dictionary('sample_dict_EN.txt', 'Latin1');
    
When called with no arguments this function returns a clone of the currently 
loaded dictionary which will be an instance of a class that extends
C<Crypt::HSXKPasswd::Dictionary>.

To load a new dictionary into an instance, call this function with arguments.
The first argument argument can be an instance of a class that extends
C<Crypt::HSXKPasswd::Dictionary>, a reference to an array of words, or the
path to a dictionary file. If either an array reference or a file path are
passed, they will be used to instantiate an instance of the class
C<Crypt::HSXKPasswd::Dictionary::Basic>, and that new instance will then be
loaded into the object. If a file path is passed, it will be assumed to be
UTF-8 encoded. If not, an optional second argument can be passed to specify the
file's encoding.

=head3 password()

    my $password = $hsxkpasswd_instance->password();
    
This function generates a random password based on the instance's loaded config
and returns it as a scalar. The function takes no arguments.

The function croaks if there is an error generating the password. The most
likely cause of and error is the random number generation, particularly if the
loaded random generation function relies on a cloud service or a non-standard
library.

=head3 passwords()

    my @passwords = $hsxkpasswd_instance->passwords(10);
    
This function generates a number of passwords and returns them all as an array.

The function uses C<password()> to generate the passwords, and hence will
croak if there is an error generating any of the requested passwords.

=head3 passwords_json()

    my $json_string = $hsxkpasswd_instance->passwords_json(10);
    
This function generates a number of passwords and returns them and the
instance's entropy stats as a JSON string representing a hashref containing an
array of passwords indexed by C<passwords>, and a hashref of entropy stats
indexed by C<stats>. The stats hashref itself is indexed by:
C<password_entropy_blind>, C<password_permutations_blind>,
C<password_entropy_blind_min>, C<password_entropy_blind_max>,
C<password_permutations_blind_max>, C<password_entropy_seen> &
C<password_permutations_seen>.

The function uses C<passwords()> to generate the passwords, and hence will
croak if there is an error generating any of the requested passwords. This
function requires that the standard Perl JSON package be installed, if not, it
will croak.

=head3 rng()

    my $rng_instance = $hsxkpasswd_instance->rng();
    $hsxkpasswd_instance->rng($rng_instance);
    
When called with no arguments this function returns currently loaded Random
Number Generator (RNG) which will be an instance of a class that extends
C<Crypt::HSXKPasswd::RNG>.

To load a new RNG into an instance, call this function with a single
argument, an instance of a class that extends
C<Crypt::HSXKPasswd::RNG>.

=head3 stats()

    my %stats = $hsxkpasswd_instance->stats();
    
This function generates a hash containing stats about the instance indexed by
the following keys:

=over 4

=item *

C<dictionary_contains_accents> - 1 if the filtered word list contains accented
letters, 0 otherwise.

=item *

C<dictionary_filter_length_min> & C<dictionary_filter_length_max> - the minimum
and maximum word lengths allowed by the dictionary filter (defined by config
keys C<word_length_min> and C<word_length_max>)

=item *

C<dictionary_source> - the source of the word list loaded into the instance.

=item *

C<dictionary_words_filtered> - the number of words loaded from the dictionary
file that meet the criteria defined by the loaded config.

=item *

C<dictionary_words_percent_available> - the percentage of the words in the
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

C<randomnumbers_source> - the class used by the instance to generate random
numbers.

=back

=head3 status()

    print $hsxkpasswd_instance->status();
    
Generates a string detailing the internal status of the instance. Below is a
sample status string:

    *DICTIONARY*
    Source: Crypt::HSXKPasswd::Dictionary::EN_Default
    # words: 1425
    # words of valid length: 1194 (84%)
    
    *CONFIG*
    case_transform: 'ALTERNATE'
    num_words: '3'
    padding_character: 'RANDOM'
    padding_characters_after: '2'
    padding_characters_before: '2'
    padding_digits_after: '2'
    padding_digits_before: '2'
    padding_type: 'FIXED'
    separator_alphabet: ['!', '$', '%', '&', '*', '+', '-', '.', '/', ':', ';', '=', '?', '@', '^', '_', '|', '~']
    separator_character: 'RANDOM'
    symbol_alphabet: ['!', '$', '%', '&', '*', '+', '-', '.', '/', ':', ';', '=', '?', '@', '^', '_', '|', '~']
    word_length_max: '8'
    word_length_min: '4'
    
    *RANDOM NUMBER CACHE*
    Random Number Generator: Crypt::HSXKPasswd::RNG::Basic
    # in cache: 0
    
    *PASSWORD STATISTICS*
    Password length: between 24 & 36
    Permutations (brute-force): between 2.91x10^47 & 1.57x10^71 (average 2.14x10^59)
    Permutations (given dictionary & config): 5.51x10^15
    Entropy (Brute-Force): between 157bits and 236bits (average 197bits)
    Entropy (given dictionary & config): 52bits
    # Random Numbers needed per-password: 9
    Passwords Generated: 0

=head3 update_config()

    $hsxkpasswd_instance->update_config({separator_character => '+'});
    
The function updates the config within an HSXKPasswd instance. A hashref with the
config options to be changed must be passed. The function returns a reference to
the instance to enable function chaining. The function will croak if the updated
config would be invalid in some way. Note that if this happens the running
config will not have been altered in any way.

=head1 DIAGNOSTICS

By default this module does all of it's error notification via the functions
C<carp()>, C<croak()>, and C<confess()> from the C<Carp> module. Optionally,
all error messages can also be printed. To enable the printing of messages,
set C<$Crypt::HSXKPasswd::LOG_ERRORS> to a truthy value. All error messages
will then be printed to the stream at C<$Crypt::HSXKPasswd::LOG_STREAM>, which
is set to C<STDERR> by default.

Ordinarily this module produces very little output, to enable more verbose
output C<$Crypt::HSXKPasswd::DEBUG> can be set to a truthy value. If this is
set, all debug messages will be printed to the stream
C<$Crypt::HSXKPasswd::LOG_STREAM>.

This module produces output at three severity levels:

=over 4

=item *

C<DEBUG> - this output is completely suppressed unless
C<$Crypt::HSXKPasswd::DEBUG> is set to a truthy value. If not suppressed debug
messages are always printed to C<$Crypt::HSXKPasswd::LOG_STREAM> (regardless of
the value of C<$Crypt::HSXKPasswd::LOG_ERRORS>).

=item *

C<WARNING> - warning messages are always thrown with C<carp()>, and also
printed to C<$Crypt::HSXKPasswd::LOG_STREAM> if
C<$Crypt::HSXKPasswd::LOG_ERRORS> evaluates to true.

=item *

C<ERROR> - error messages are usually thrown with C<croak()>, but will be
thrown with C<confess()> if C<$Crypt::HSXKPasswd::DEBUG> evaluates to true. If
C<$Crypt::HSXKPasswd::LOG_ERRORS> evaluates to true errors are also printed to
C<$Crypt::HSXKPasswd::LOG_STREAM>, including a stack trace if
C<$Crypt::HSXKPasswd::DEBUG> evaluates to true and the module
C<Devel::StackTrace> is installed.


=back

=head1 CONFIGURATION AND ENVIRONMENT

This module does not currently support configuration files, nor does it
currently interact with the environment. It may do so in future versions.

=head1 DEPENDENCIES

This module requires the following Perl modules:

=over 4

=item *

C<Carp> - L<http://search.cpan.org/perldoc?Carp>

=item *

C<DateTime> - L<http://search.cpan.org/perldoc?DateTime>

=item *

C<English> - L<http://search.cpan.org/perldoc?English>

=item *

C<List::MoreUtils> - L<http://search.cpan.org/perldoc?List%3A%3AMoreUtils>

=item *

C<Math::BigInt> - L<http://search.cpan.org/perldoc?Math%3A%3ABigInt>

=item *

C<Math::Round> - L<http://search.cpan.org/perldoc?Math%3A%3ARound>

=item *

C<Params::Validate> - L<http://search.cpan.org/perldoc?Params%3A%3AValidate>

=item *

C<Scalar::Util> - L<http://search.cpan.org/perldoc?Scalar%3A%3AUtil>

=item *

C<strict> - L<http://search.cpan.org/perldoc?strict>

=item *

C<Text::Unidecode> - L<http://search.cpan.org/perldoc?Text%3A%3AUnidecode>

=item *

C<Type::Library> - L<http://search.cpan.org/perldoc?Type%3A%3ALibrary>

=item *

C<Type::Tiny> - L<http://search.cpan.org/perldoc?Type%3A%3ATiny>

=item *

C<Types::Standard> - L<http://search.cpan.org/perldoc?Types%3A%3AStandard>

=item *

C<warnings> - L<http://search.cpan.org/perldoc?warnings>

=back

The module can also optionally use the following Perl modules:

=over 4

=item *

C<Data::Entropy::Algorithms> - L<http://search.cpan.org/perldoc?Data%3A%3AEntropy%3A%3AAlgorithms>

Used by the RNG class C<Crypt::HSXKPasswd::RNG::Data_Entropy>.

=item *

C<Devel::StackTrace> - L<http://search.cpan.org/perldoc?Devel%3A%3AStackTrace>

Used for printing stack traces with error messages if
C<$XKPasswd::DEBUG> and C<$XKPasswd::LOG_ERRORS> both evaluate to true. If the
module is not installed the stack traces will be omitted from the log messages.

=item *

C<Email::Valid> - L<http://search.cpan.org/perldoc?Email%3A%3AValid>

Used by the Random.Org RNG class C<Crypt::HSXKPasswd::RNG::RandomDotOrg>.

=item *

C<JSON> - L<http://search.cpan.org/perldoc?JSON>

Used for loading and exporting config hashrefs as JSON strings. Needed if the
named parameter C<config_json> is passed to the constructor or C<hsxkpasswd()>,
if a string is passed to C<config()>, or if any function contianing the word
C<json> in the function name is called.

=item *

C<LWP::UserAgent> - L<http://search.cpan.org/perldoc?LWP%3A%3AUserAgent>

Used by the Random.Org RNG class C<Crypt::HSXKPasswd::RNG::RandomDotOrg>.

=item *

C<Math::Random::Secure> - L<http://search.cpan.org/perldoc?Math%3A%3ARandom%3A%3ASecure>

Used by the RNG class C<Crypt::HSXKPasswd::RNG::Math_Random_Secure>.

=item *

C<Mozilla::CA> - L<http://search.cpan.org/perldoc?Mozilla%3A%3ACA>

Indirectly required by the Random.Org RNG class
C<Crypt::HSXKPasswd::RNG::RandomDotOrg> because without it C<LWP::UserAgent>
can't use HTTPS, and the Random.Org API uses HTTPS.

=item *

C<URI> - L<http://search.cpan.org/perldoc?URI>

Used by the Random.Org RNG class C<Crypt::HSXKPasswd::RNG::RandomDotOrg>.

=back

=head1 INCOMPATIBILITIES

This module has no known incompatibilities.

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.

Please report any bugs you may find on the module's GitHub page:
L<https://github.com/bbusschots/xkpasswd.pm>.

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2014-15, Bart Busschots T/A Bartificer Web Solutions
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

The following components of this package are covered by the more restrictive
GPL V2 license L<https://www.gnu.org/licenses/gpl-2.0.html>:

=over 4

=item *

The C<share/sample_dict_DE.txt> text file.

=item *

The C<Crypt::HSXKPasswd::Dictionary::DE> Perl module.

=item *

The C<share/sample_dict_FR.txt> text file.

=item *

The C<Crypt::HSXKPasswd::Dictionary::FR> Perl module.

=item *

The C<share/sample_dict_IT.txt> text file.

=item *

The C<Crypt::HSXKPasswd::Dictionary::IT> Perl module.

=item *

The C<share/sample_dict_NL.txt> text file.

=item *

The C<Crypt::HSXKPasswd::Dictionary::NL> Perl module.

=item *

The C<share/sample_dict_PT.txt> text file.

=item *

The C<Crypt::HSXKPasswd::Dictionary::PT> Perl module.

=back

=head1 AUTHOR

Bart Busschots (L<mailto:bart@bartificer.net>)