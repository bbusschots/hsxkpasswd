package Crypt::HSXKPasswd::Types;

# inhert from Type::Library
use parent Type::Library;

# import required modules
use strict;
use warnings;
use English qw( -no_match_vars );
use Carp; # for nicer 'exceptions' for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions
use List::MoreUtils qw( uniq );
use Data::Dumper; # for generating sane error messages
use Type::Tiny;
use Types::Standard qw( :types );

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

#==============================================================================#
# Custom Type Library for Crypt::HSXKPasswd
#==============================================================================#
#
# A library of custom Type::Tiny types for use in the various Crypt::HSXKPasswd
# packages.
#
#==============================================================================#

#
# === CONSTANTS ===============================================================#
#

# version info
use version; our $VERSION = qv('1.2');

#
# === Define The Fundamental Types ============================================#
#

# add a type for Perl package names
my $PERL_PACKAGE_NAME_ENGLISH = q{a valid Perl Package Name like 'Crypt::HSXKPasswd'};
my $PERL_PACKAGE_NAME = Type::Tiny->new(
    name => 'PerlPackageName',
    parent => Str,
    constraint => sub{ m/^[a-zA-Z_]\w*(?:[:]{2}\w+)*$/sx; }, ## no critic (ProhibitEnumeratedClasses)
    message => sub{
        return var_to_string($_).qq{ is not $PERL_PACKAGE_NAME_ENGLISH};
    },
    my_methods => {
        english => sub {return $PERL_PACKAGE_NAME_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($PERL_PACKAGE_NAME);

# add a type for positive integers (including 0)
my $POSITIVE_INTEGER_ENGLISH = 'an integer greater than or equal to zero';
my $POSITIVE_INTEGER = Type::Tiny->new(
    name => 'PositiveInteger',
    parent => Int,
    constraint => sub{
        return $_ >= 0;
    },
    message => sub{
        return var_to_string($_).qq{ is not $POSITIVE_INTEGER_ENGLISH};
    },
    my_methods => {
        english => sub {return $POSITIVE_INTEGER_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($POSITIVE_INTEGER);

# add a type for positive integers (including 0)
my $NON_ZERO_POSITIVE_INTEGER_ENGLISH = 'an integer greater than zero';
my $NON_ZERO_POSITIVE_INTEGER = Type::Tiny->new(
    name => 'NonZeroPositiveInteger',
    parent => Int,
    constraint => sub{
        return $_ > 0;
    },
    message => sub{
        return var_to_string($_).qq{ is not $NON_ZERO_POSITIVE_INTEGER_ENGLISH};
    },
    my_methods => {
        english => sub {return $NON_ZERO_POSITIVE_INTEGER_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($NON_ZERO_POSITIVE_INTEGER);

# add a type for strings of at least one character
my $NON_EMPTY_STRING_ENGLISH = 'a string contianing at least one character';
my $NON_EMPTY_STRING = Type::Tiny->new(
    name => 'NonEmptyString',
    parent => Str,
    constraint => sub{
        return length $_ > 0;
    },
    message => sub{
        return var_to_string($_).qq{ is not $NON_EMPTY_STRING_ENGLISH};
    },
    my_methods => {
        english => sub {return $NON_EMPTY_STRING_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($NON_EMPTY_STRING);

# add a type for a single letter (a single alpha grapheme)
my $LETTER_ENGLISH = q{a string containing exactly one letter};
my $LETTER = Type::Tiny->new(
    name => 'Letter',
    parent => Str,
    constraint => sub{
        return m/^\pL$/sx;
    },
    message => sub{
        return var_to_string($_).qq{ is not a Letter (must be $LETTER_ENGLISH)};
    },
    my_methods => {
        english => sub {return $LETTER_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($LETTER);

# add a type for words (a grouping of alpha characters at least four graphemes
# long)
my $WORD_ENGLISH = q{a string of only letters at least four long};
my $WORD = Type::Tiny->new(
    name => 'Word',
    parent => Str,
    constraint => sub{
        return m/^\pL{4,}$/sx;
    },
    message => sub{
        return var_to_string($_).qq{ is not a Word (must be $WORD_ENGLISH)};
    },
    my_methods => {
        english => sub {return $WORD_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($WORD);

# add a type for a single symbol (a single non-letter unicode grapheme)
my $SYMBOL_ENGLISH = 'a string containing exactly one non-letter character';
my $SYMBOL = Type::Tiny->new(
    name => 'Symbol',
    parent => Str,
    constraint => sub{
        return m/^\X$/sx && m/^[^\pL]$/sx;
    },
    message => sub{
        return var_to_string($_).qq{ is not a Symbol (must be $SYMBOL_ENGLISH)};
    },
    my_methods => {
        english => sub {return $SYMBOL_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($SYMBOL);

# add a type for symbol alphabets - array refs containing only, and at least 2,
# single-character strings
my $SYMBOL_ALPHABET_ENGLISH = 'a reference to an array of distinct Symbols at least two long';
my $SYMBOL_ALPHABET = Type::Tiny->new(
    name => 'SymbolAlphabet',
    parent => ArrayRef[$SYMBOL],
    constraint => sub{
        my @unique_symbols = uniq(@{$_});
        return scalar @unique_symbols >= 2;
    },
    message => sub{
        return var_to_string($_).qq{ is not a Symbol Alphabet (must be $SYMBOL_ALPHABET_ENGLISH)};
    },
    my_methods => {
        english => sub {return $SYMBOL_ALPHABET_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($SYMBOL_ALPHABET);

# add a type for word lengths - integers greater than 3
my $WORD_LENGTH_ENGLISH = 'an integer greater than 3';
my $WORD_LENGTH = Type::Tiny->new(
    name => 'WordLength',
    parent => Int,
    constraint => sub{
        return $_ > 3;
    },
    message => sub{
        return var_to_string($_).qq{ is not a valid Word Length (must be $WORD_LENGTH_ENGLISH)};
    },
    my_methods => {
        english => sub {return $WORD_LENGTH_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($WORD_LENGTH);

# add a type for word lengths - integers greater than 3
my $TRUE_FALSE_ENGLISH = '1 to indicate true, or 0, undef, or the empty string to indicate false';
my $TRUE_FALSE = Type::Tiny->new(
    name => 'TrueFalse',
    parent => Bool,
    message => sub{
        return var_to_string($_).qq{ is not a valid True/False value (must be $TRUE_FALSE_ENGLISH)};
    },
    my_methods => {
        english => sub {return $TRUE_FALSE_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($TRUE_FALSE);

#
# === Define HSXKPasswd-specific general Types ================================#
#

# add a type for upper-case identifiers
my $UPPERCASE_IDENTIFIER_ENGLISH = 'a non-empty string containging only upper-case un-accented letters, digits and underscores';
my $UPPERCASE_IDENTIFIER = Type::Tiny->new(
    name => 'UppercaseIdentifier',
    parent => Str,
    constraint => sub{
        return m/^[A-Z0-9_]+$/sx; ## no critic (ProhibitEnumeratedClasses)
    },
    message => sub{
        return var_to_string($_).qq{ is not $UPPERCASE_IDENTIFIER_ENGLISH};
    },
    my_methods => {
        english => sub {return $UPPERCASE_IDENTIFIER_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($UPPERCASE_IDENTIFIER);

# add a type for entropy warning levels
my $ENTROPY_WARNING_LEVEL_ENGLISH = q{one of 'ALL', 'BLIND', or 'NONE'};
my $ENTROPY_WARNING_LEVEL = Type::Tiny->new(
    name => 'EntropyWarningLevel',
    parent => Str,
    constraint => sub{
        return m/^[A-Z0-9_]+$/sx; ## no critic (ProhibitEnumeratedClasses)
    },
    message => sub{
        return var_to_string($_).qq{ is not a valid entropy warning level, must be $ENTROPY_WARNING_LEVEL_ENGLISH};
    },
    my_methods => {
        english => sub {return $ENTROPY_WARNING_LEVEL_ENGLISH;},
    },
);
$ENTROPY_WARNING_LEVEL->coercion()->add_type_coercions(Str, q{uc $_}); ## no critic (RequireInterpolationOfMetachars)
__PACKAGE__->meta->add_type($ENTROPY_WARNING_LEVEL);

#
# === Define the Config Keys and related Types ================================#
#

# add a type for config key definitions - a hashref with the correct indexes and values
my $CONFIG_KEY_DEFINITION_ENGLISH = q{a reference to a hash  mapping 'required' to a true/false value, 'expects' to a non-empty string, and 'type' to a Type::Tiny object};
my $CONFIG_KEY_DEFINITION = Type::Tiny->new(
    name => 'ConfigKeyDefinition',
    parent => Dict[required => $TRUE_FALSE, expects => $NON_EMPTY_STRING, type => InstanceOf['Type::Tiny']] ,
    message => sub{
        return var_to_string($_).qq{ is not a valid Config Key Definition (must be $CONFIG_KEY_DEFINITION_ENGLISH)};
    },
    my_methods => {
        english => sub {return $CONFIG_KEY_DEFINITION_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($CONFIG_KEY_DEFINITION);

# define the config keys
my $_KEYS = {
    allow_accents => {
        required => 0,
        expects => $TRUE_FALSE_ENGLISH,
        type => Type::Tiny->new(
            parent => $TRUE_FALSE,
            message => sub {
                return _config_key_message($_, 'allow_accents', $TRUE_FALSE_ENGLISH);
            },
        ),
    },
    symbol_alphabet => {
        required => 0,
        expects => $SYMBOL_ALPHABET_ENGLISH,
        type => Type::Tiny->new(
            parent => $SYMBOL_ALPHABET,
            message => sub {
                return _config_key_message($_, 'key symbol_alphabet', $SYMBOL_ALPHABET_ENGLISH);
            },
        ),
    },
    separator_alphabet => {
        required => 0,
        expects => $SYMBOL_ALPHABET_ENGLISH,
        type => Type::Tiny->new(
            parent => $SYMBOL_ALPHABET,
            message => sub {
                return _config_key_message($_, 'separator_alphabet', $SYMBOL_ALPHABET_ENGLISH);
            },
        ),
    },
    padding_alphabet => {
        required => 0,
        expects => $SYMBOL_ALPHABET_ENGLISH,
        type => Type::Tiny->new(
            parent => $SYMBOL_ALPHABET,
            message => sub {
                return _config_key_message($_, 'padding_alphabet', $SYMBOL_ALPHABET_ENGLISH);
            },
        ),
    },
    word_length_min => {
        required => 1,
        expects => $WORD_LENGTH_ENGLISH,
        type => Type::Tiny->new(
            parent => $WORD_LENGTH,
            message => sub {
                return _config_key_message($_, 'word_length_min', $WORD_LENGTH_ENGLISH);
            },
        ),
    },
    word_length_max => {
        required => 1,
        expects => $WORD_LENGTH_ENGLISH,
        type => Type::Tiny->new(
            parent => $WORD_LENGTH,
            message => sub {
                return _config_key_message($_, 'word_length_max', $WORD_LENGTH_ENGLISH);
            },
        ),
    },
    padding_digits_before => {
        required => 1,
        expects => $POSITIVE_INTEGER_ENGLISH,
        type => Type::Tiny->new(
            parent => $POSITIVE_INTEGER,
            message => sub {
                return _config_key_message($_, 'padding_digits_before', $POSITIVE_INTEGER_ENGLISH);
            },
        ),
    },
    padding_digits_after => {
        required => 1,
        expects => $POSITIVE_INTEGER_ENGLISH,
        type => Type::Tiny->new(
            parent => $POSITIVE_INTEGER,
            message => sub {
                return _config_key_message($_, 'padding_digits_after', $POSITIVE_INTEGER_ENGLISH);
            },
        ),
    },
    padding_characters_before => {
        required => 0,
        expects => $POSITIVE_INTEGER_ENGLISH,
        type => Type::Tiny->new(
            parent => $POSITIVE_INTEGER,
            message => sub {
                return _config_key_message($_, 'padding_characters_before', $POSITIVE_INTEGER_ENGLISH);
            },
        ),
    },
    padding_characters_after => {
        required => 0,
        expects => $POSITIVE_INTEGER_ENGLISH,
        type => Type::Tiny->new(
            parent => $POSITIVE_INTEGER,
            message => sub {
                return _config_key_message($_, 'padding_characters_after', $POSITIVE_INTEGER_ENGLISH);
            },
        ),
    },
};
$_KEYS->{num_words} = {
    required => 1,
    expects => 'an integer greater than or equal to two',
};
$_KEYS->{num_words}->{type} = Type::Tiny->new(
    parent => Int,
    constraint => sub{
        return $_ >= 2;
    },
    message => sub {
        return _config_key_message($_, 'num_words', $_KEYS->{num_words}->{expects});
    },
);
$_KEYS->{separator_character} = {
    required => 1,
    expects => q{a single Symbol or one of the special values: 'NONE' or 'RANDOM'},
};
$_KEYS->{separator_character}->{type} = Type::Tiny->new(
    parent => Str,
    constraint => sub{
        return $SYMBOL->check($_) || m/^(?:NONE)|(?:RANDOM)$/sx;
    },
    message => sub {
        return _config_key_message($_, 'separator_character', $_KEYS->{separator_character}->{expects});
    },
);
$_KEYS->{padding_type} = {
    required => 1,
    expects => q{one of the values 'NONE', 'FIXED', or 'ADAPTIVE'},
};
$_KEYS->{padding_type}->{type} = Type::Tiny->new(
    parent => Enum[qw( NONE FIXED ADAPTIVE )],
    message => sub {
        return _config_key_message($_, 'key padding_type', $_KEYS->{padding_type}->{expects});
    },
);
$_KEYS->{pad_to_length} = {
    required => 0,
    expects => 'an integer greater than or equal to twelve',
};
$_KEYS->{pad_to_length}->{type} = Type::Tiny->new(
    parent => Int,
    constraint => sub{
        return $_ >= 12;
    },
    message => sub {
        return _config_key_message($_, 'pad_to_length', $_KEYS->{pad_to_length}->{expects});
    },
);
$_KEYS->{padding_character} = {
    required => 0,
    expects => q{a single Symbol or one of the special values: 'NONE', 'RANDOM', or 'SEPARATOR'},
};
$_KEYS->{padding_character}->{type} = Type::Tiny->new(
    parent => Str,
    constraint => sub{
        return $SYMBOL->check($_) || m/^(?:NONE)|(?:RANDOM)|(?:SEPARATOR)$/sx;
    },
    message => sub {
        return _config_key_message($_, 'padding_character', $_KEYS->{padding_character}->{expects});
    },
);
$_KEYS->{case_transform} = {
    required => 0,
    expects => q{one of the values 'NONE' , 'UPPER', 'LOWER', 'CAPITALISE', 'INVERT', 'ALTERNATE', or 'RANDOM'},
};
$_KEYS->{case_transform}->{type} = Type::Tiny->new(
    parent => Enum[qw( NONE UPPER LOWER CAPITALISE INVERT ALTERNATE RANDOM )],
    message => sub {
        return _config_key_message($_, 'case_transform', $_KEYS->{case_transform}->{expects});
    },
);
$_KEYS->{character_substitutions} = {
    required => 0,
    expects => 'a reference to a hash mapping zero or more Letters to their replacements which must be strings',
};
$_KEYS->{character_substitutions}->{type} = Type::Tiny->new(
    parent => Map[$LETTER, Defined],
    message => sub {
        return _config_key_message($_, 'character_substitutions', $_KEYS->{character_substitutions}->{expects});
    },
);
$_KEYS->{substitution_mode} = {
    required => 0,
    expects => q{one of the values 'ALWAYS', NEVER, or 'RANDOM'},
};
$_KEYS->{substitution_mode}->{type} = Type::Tiny->new(
    parent => Enum[qw( ALWAYS NEVER RANDOM )],
    message => sub {
        return _config_key_message($_, 'substitution_mode', $_KEYS->{substitution_mode}->{expects});
    }
);


# add a type for config key names
my $CONFIG_KEY_NAME_ENGLISH = 'for a list of all defined config key names see the docs, or the output from the function Crypt::HSXKPasswd->defined_config_keys()';
my $CONFIG_KEY_NAME = Type::Tiny->new(
    name => 'ConfigKeyName',
    parent => Str,
    constraint => sub{
        my $test_val = $_;
        foreach my $key_name (keys %{$_KEYS}){
            if($test_val eq $key_name){
                return 1;
            }
        }
        return 0;
    },
    message => sub{
        return var_to_string($_).qq{ is not a defined Config Name ($CONFIG_KEY_NAME_ENGLISH)};
    },
    my_methods => {
        english => sub {return 'a defined config name - '.$CONFIG_KEY_NAME_ENGLISH;},
    },
);
$CONFIG_KEY_NAME->coercion()->add_type_coercions(Str, q{lc $_}); ## no critic (RequireInterpolationOfMetachars)
__PACKAGE__->meta->add_type($CONFIG_KEY_NAME);

# add a type for a config key name-value pair - must be a reference to a
# hash with exactly one key, which must be a valid config key, and the
# value accompanying that key must be valid for the given key
my $CONFIG_KEY_ASSIGNMENT_ENGLISH = 'a mapping from a valid config key name to a valid value for that key';
my $CONFIG_KEY_ASSIGNMENT = Type::Tiny->new(
    name => 'ConfigKeyAssignment',
    parent => Map[$CONFIG_KEY_NAME, Item],
    coercion => 1,
    constraint => sub{
        # make sure there is exactly 1 key
        unless(scalar keys %{$_} == 1){
            return 0;
        }
        
        # extract the key and value
        my $key = (keys %{$_})[0];
        my $val = $_->{$key};
        
        # validate the value and return the result
        return $_KEYS->{$key}->{type}->check($val);
    },
    message => sub{
        # if we were not even passed a single-keyed hash, give the basic error
        unless(HashRef->check($_) && scalar keys %{$_} == 1){
            return var_to_string($_).qq{ is not a valid Config Key Assignment (must be $CONFIG_KEY_ASSIGNMENT_ENGLISH)};
        }
        
        # extract the key and value
        my $key = (keys %{$_})[0];
        my $val = $_->{$key};
        
        # if the config key is not valid, offer help with that
        unless($CONFIG_KEY_NAME->check($key)){
            return var_to_string($_).' is not a valid Config Key Assignment because the specified key name '.var_to_string($key). " is not defined - $CONFIG_KEY_NAME_ENGLISH";
        }
        
        # if we got here the problem must be with the value, so give useful info about the expected value
        return var_to_string($_).' is not a valid Config Key Assignment because '.$_KEYS->{$key}->{type}->get_message($val);
    },
    my_methods => {
        english => sub {return $CONFIG_KEY_ASSIGNMENT_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($CONFIG_KEY_ASSIGNMENT);

# a type for config overrides
my $CONFIG_OVERRIDE_ENGLISH = 'a reference to a hash containing one or more Config Key Assignments';
my $CONFIG_OVERRIDE = Type::Tiny->new(
    name => 'ConfigOverride',
    parent => Map[$CONFIG_KEY_NAME, Item],
    coercion => 1,
    constraint => sub{
        my %test_hash = %{$_};
        
        # make sure at least one key is specified
        unless(scalar keys %test_hash){
            return 0;
        }
        
        # make sure each key specified maps to a valid value
        foreach my $key (keys %test_hash){
            unless($CONFIG_KEY_ASSIGNMENT->check({$key => $test_hash{$key}})){
                return 0;
            }
        }
        
        # if we got here, all is well, so return 1
        return 1;
    },
    message => sub{
        # if we were not even passed a hash, give the basic error
        unless(HashRef->check($_)){
            return var_to_string($_).qq{ is not a valid Config Override (must be $CONFIG_OVERRIDE_ENGLISH)};
        }
        
        # get an easy reference to the hash
        my %overrides = %{$_};
        
        # make sure at least one key is present
        unless(scalar keys %overrides){
            return var_to_string($_)." is not a valid Config Override because it is empty (must be $CONFIG_OVERRIDE_ENGLISH)";
        }
        
        # check for invalid names
        my @invalid_key_names = _extract_invalid_key_names(\%overrides);
        if(scalar @invalid_key_names){
            my $msg = var_to_string($_)." is not a valid Config Override because it contains one or more invalid Config Key Names:\n";
            foreach my $key (sort @invalid_key_names){
                $msg .= "* '$key'\n";
            }
            $msg .= "($CONFIG_KEY_NAME_ENGLISH)";
            return $msg;
        }
        
        # it must be down to invalid values, find the offending key(s)
        my @invalid_valued_keys = _extract_invalid_valued_keys(\%overrides);
        if(scalar @invalid_valued_keys){
            my $msg = var_to_string($_)." is not a valid Config Override because one of more of the config keys specify an invalid value:\n";
            foreach my $key_name (@invalid_valued_keys){
                $msg .= '* '.$_KEYS->{$key_name}->{type}->get_message($overrides{$key_name})."\n";
            }
            chomp $msg;
            return $msg;
        }
        
        # it should not be possible to get here, but to be sure to be sure, return a basic message
        return var_to_string($_)." is not a valid Config Override for an unexpected reason - (must be $CONFIG_OVERRIDE_ENGLISH)";
    },
    my_methods => {
        english => sub {return $CONFIG_OVERRIDE_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($CONFIG_OVERRIDE);

# add a type for a valid config hashref
my $CONFIG_ENGLISH = 'a reference to a hash indexed only by valid Config Names, containing only valid values, with all required config names present, and all config key interdependencies satisfied';
my $CONFIG = Type::Tiny->new(
    name => 'Config',
    parent => $CONFIG_OVERRIDE,
    coercion => 1,
    constraint => sub{
        # check for missing required keys
        my @missing_required_keys = _extract_missing_required_keys($_);
        if(scalar @missing_required_keys){
            return 0;
        }
        
        # check for unfulfilled dependencies
        my @unfulfilled_key_interdependencies = _extract_unfulfilled_key_interdependencies($_);
        if(scalar @unfulfilled_key_interdependencies){
            return 0;
        }
        
        # if we got here, all is well, so return 1
        return 1;
    },
    my_methods => {
        english => sub {return $CONFIG_ENGLISH;},
    },
    message => sub{
        # if we were not even passed a hash, give the basic error
        unless(HashRef->check($_)){
            return var_to_string($_).qq{ is not a valid Config (must be $CONFIG_ENGLISH)};
        }
        
        # get an easy reference to the hash
        my $config = $_;
        
        # check for invalid names
        my @invalid_key_names = _extract_invalid_key_names($config);
        if(scalar @invalid_key_names){
            my $msg = var_to_string($_)." is not a valid Config because it contains one or more invalid Config Key Names:\n";
            foreach my $key (sort @invalid_key_names){
                $msg .= "* '$key'\n";
            }
            $msg .= "($CONFIG_KEY_NAME_ENGLISH)";
            return $msg;
        }
        
        # check for missing required keys
        my @missing_required_keys = _extract_missing_required_keys($_);
        if(scalar @missing_required_keys){
            my $msg = var_to_string($_)." is not a valid Config because one or more required config keys are missing:\n";
            foreach my $key (sort @missing_required_keys){
                $msg .= "'$key'\n";
            }
            chomp $msg;
            return $msg;
        }
        
        # check for invalid values and find the offending key(s)
        my @invalid_valued_keys = _extract_invalid_valued_keys($config);
        if(scalar @invalid_valued_keys){
            my $msg = var_to_string($_)." is not a valid Config because one of more of the config keys specify invalid values:\n";
            foreach my $key_name (@invalid_valued_keys){
                $msg .= '* '.$_KEYS->{$key_name}->{type}->get_message($config->{$key_name})."\n";
            }
            chomp $msg;
            return $msg;
        }
        
        # that means it must be unfulfilled interdependencies
        my @unfulfilled_key_interdependencies = _extract_unfulfilled_key_interdependencies($_);
        if(scalar @unfulfilled_key_interdependencies){
            my $msg = var_to_string($_)." is not a valid Config because one of more interdependencies between config keys is not fullfilled:\n";
            foreach my $problem (@unfulfilled_key_interdependencies){
                $msg .= "* $problem\n";
            }
            chomp $msg;
            return $msg;
        }
        
        
        # it should not be possible to get here, but to be sure to be sure, return a basic message
        return var_to_string($_)." is not a valid Config for an unexpected reason - (must be $CONFIG_ENGLISH)";
    },
);
__PACKAGE__->meta->add_type($CONFIG);

#
# === Define the Presets and related Types ====================================#
#

# add a type for preset definitions - a hashref with the correct indexes and values
my $PRESET_DEFINITION_ENGLISH = q{a reference to a hash  mapping 'description' to a non-empty string, and 'config' to a valid Config};
my $PRESET_DEFINITION = Type::Tiny->new(
    name => 'PresetDefinition',
    parent => Dict[description => $NON_EMPTY_STRING, config => $CONFIG] ,
    message => sub{
        return var_to_string($_).qq{ is not a valid Preset Definition (must be $PRESET_DEFINITION_ENGLISH)};
    },
    my_methods => {
        english => sub {return $PRESET_DEFINITION_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($PRESET_DEFINITION);

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
        description => 'A preset for websites that insit passwords not be longer than 16 characters. WARNING - only use this preset if you have to, it is too short to be acceptably secure and will always generate entropy warnings for the case where the config and dictionary are known.',
        config => {
            symbol_alphabet => [qw{! @ $ % ^ & * - _ + = : | ~ ? / . ;}],
            word_length_min => 4,
            word_length_max => 4,
            num_words => 3,
            separator_character => 'RANDOM',
            padding_digits_before => 0,
            padding_digits_after => 2,
            padding_type => 'NONE',
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
            padding_alphabet => [qw{- : . ! ? @ &}],
            separator_alphabet => [qw{- : . @}, q{,}, q{ }],
            word_length_min => 4,
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
        description => 'A preset for generating passwords similar to the example in the original XKCD cartoon, but with an extra word, a dash to separate the random words, and the capitalisation randomised to add sufficient entropy to avoid warnings.',
        config => {
            word_length_min => 4,
            word_length_max => 8,
            num_words => 5,
            separator_character => q{-},
            padding_digits_before => 0,
            padding_digits_after => 0,
            padding_type => 'NONE',
            case_transform => 'RANDOM',
            allow_accents => 0,
        },
    },
};

# add a type for config key names
my $PRESET_NAME_ENGLISH = 'for a list of all defined preset names see the docs, or the output from the function Crypt::HSXKPasswd->defined_presets()';
my $PRESET_NAME = Type::Tiny->new(
    name => 'PresetName',
    parent => Str,
    constraint => sub{
        my $test_val = $_;
        foreach my $preset_name (keys %{$_PRESETS}){
            if($test_val eq $preset_name){
                return 1;
            }
        }
        return 0;
    },
    message => sub{
        return var_to_string($_).qq{ is not a defined Preset Name ($PRESET_NAME_ENGLISH)};
    },
    my_methods => {
        english => sub {return 'a defined preset name - '.$PRESET_NAME_ENGLISH;},
    },
);
$PRESET_NAME->coercion()->add_type_coercions(Str, q{uc $_}); ## no critic (RequireInterpolationOfMetachars)
__PACKAGE__->meta->add_type($PRESET_NAME);

#
# === Define .hsxkpassdrc file related Types ==================================#
#

my $RCFILE_DATA_ENGLISH = q{a reference to a hash defining one or more of: custom presets, default_entropy_warnings, default dictionary, and default random number generator};
my $RCFILE_DATA = Type::Tiny->new(
    name => 'RCFileData',
    parent => Dict[
        custom_presets => Optional[Map[$UPPERCASE_IDENTIFIER, $PRESET_DEFINITION]],
        default_entropy_warnings => Optional[$ENTROPY_WARNING_LEVEL],
        default_dictionary => Optional[Dict[
            package => Optional[$PERL_PACKAGE_NAME],
            package_constructor_args => Optional[ArrayRef],
            file => Optional[$NON_EMPTY_STRING],
        ]],
        default_rng => Optional[Dict[
            package => $PERL_PACKAGE_NAME,
            package_constructor_args => Optional[ArrayRef],
        ]],
    ],
    constraint => sub{
        # if there is a default dictionary section, make sure there is exactly one source specified
        if($_->{default_dictionary}){
            unless($_->{default_dictionary}->{package} || $_->{default_dictionary}->{file}){
                return 0;
            }
            if($_->{default_dictionary}->{package} && $_->{default_dictionary}->{file}){
                return 0;
            }
        }
        
        # if we got here, all is OK
        return 1;
    },
    message => sub{
        my $basic_msg = var_to_string($_).qq{ is not a valid hsxkpasswdrc file data structure (must be $RCFILE_DATA_ENGLISH)};
        # make sure we at least have a hash
        unless(HashRef->check($_)){
            return $basic_msg;
        }
        
        # make sure there are no invalid keys present
        my @invalid_keys = ();
        foreach my $key (sort keys %{$_}){
            unless($key =~ m/^(?:custom_presets)|(?:default_entropy_warnings)|(?:default_dictionary)|(?:default_rng)$/sx){ ## no critic (ProhibitComplexRegexes)
                push @invalid_keys, $key;
            }
        }
        if(scalar @invalid_keys){
            return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it is indexed by one or more invalid keys: }.(join q{, }, @invalid_keys);
        }
        
        # if defined, make sure each preset is valid
        if($_->{custom_presets}){
            # make sure custom_presets is a hashref
            unless(HashRef->check($_->{custom_presets})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it defines the key 'custom_presets', but not as a reference to a hash};
            }
            
            # make sure all the preset names are valid
            my @invalid_preset_names = ();
            foreach my $preset_name (sort keys %{$_->{custom_presets}}){
                unless($UPPERCASE_IDENTIFIER->check($preset_name)){
                    push @invalid_preset_names, $preset_name;
                }
            }
            if(scalar @invalid_preset_names){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it contains one or more invalid custom preset names: }.(join q{, }, @invalid_preset_names).qq{ (each preset name must be $UPPERCASE_IDENTIFIER_ENGLISH)};
            }
            
            # test each preset
            my @invalid_preset_defs = ();
            ## no critic (ProhibitDeepNests);
            foreach my $preset_name (sort keys %{$_->{custom_presets}}){
                unless($PRESET_DEFINITION->check($_->{custom_presets}->{$preset_name})){
                    # make sure the preset does not define any invalid keys
                    my @invalid_preset_keys = ();
                    foreach my $preset_key (sort keys %{$_->{custom_presets}->{$preset_name}}){
                        unless($preset_key =~ m/^(?:description)|(?:config)$/sx){
                            push @invalid_preset_keys, $preset_key;
                        }
                    }
                    if(scalar @invalid_preset_keys){
                        return var_to_string($_).qq{ is not a valid hsxkpasswdrc file data structure because the custom preset '$preset_name' is indexed by one or more invalid keys: }.(join q{, }, @invalid_preset_keys);
                    }
                    
                    # if the preset is valid except for the config, print the problem with the config
                    # NOTE - this code is potentially brittle - if the test for a preset definition
                    #     is changed, this code could fail to be triggered, leading to less helpful
                    #     error message. Because of the final check against config, the message cannot
                    #     be triggered if the config is valid though, so at least the code can't give a
                    #     BS answer!
                    if(
                        $_->{custom_presets}->{$preset_name}->{description} &&
                        $NON_EMPTY_STRING->check($_->{custom_presets}->{$preset_name}->{description}) &&
                        $_->{custom_presets}->{$preset_name}->{config} &&
                        HashRef->check($_->{custom_presets}->{$preset_name}->{config}) &&
                        !$CONFIG->check($_->{custom_presets}->{$preset_name}->{config})
                    ){
                        return return var_to_string($_).qq{ is not a valid hsxkpasswdrc file data structure because it defines a custom preset '$preset_name' which is invalid:\n}.$CONFIG->get_message($_->{custom_presets}->{$preset_name}->{config});
                    }
                    
                    # otherwise, just report that there is a problem with the definition
                    push @invalid_preset_defs, $preset_name;
                }
            }
            ## use critic
            if(scalar @invalid_preset_defs){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it contains one or more invalid preset definitions: }.(join q{, }, @invalid_preset_defs).qq{ (each preset definition must be $PRESET_DEFINITION_ENGLISH)};
            }
        }
        
        # if defined, make sure the default entropy warning level is valid
        if($_->{default_entropy_warnings}){
            unless($ENTROPY_WARNING_LEVEL->check($_->{default_entropy_warnings})){
                return var_to_string($_).qq{ is not a valid hsxkpasswdrc file data structure because it contains an invalid value for the key 'default_entropy_warnings', which must be $ENTROPY_WARNING_LEVEL_ENGLISH)}; 
            }
        }
        
        # if defined, make sure the default dictionary is valid
        if($_->{default_dictionary}){
            # make sure it is a hashref
            unless(HashRef->check($_->{default_dictionary})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it defines the key 'default_dictionary', but not as a reference to a hash};
            }
            
            # make sure there are no invalid keys
            my @invalid_dict_keys = ();
            foreach my $key (sort keys %{$_->{default_dictionary}}){
                unless($key =~ m/^(?:package)|(?:package_constructor_args)|(?:file)$/sx){
                    push @invalid_dict_keys, $key;
                }
            }
            if(scalar @invalid_dict_keys){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary' is indexed by one or more invalid keys: }.(join q{, }, @invalid_dict_keys);
            }
            
            # make sure each key is valid
            if($_->{default_dictionary}->{package} && !$PERL_PACKAGE_NAME->check($_->{default_dictionary}->{package})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary'->'package' is not a valid Perl package name}; 
            }
            if($_->{default_dictionary}->{package_constructor_args} && !ArrayRef->check($_->{default_dictionary}->{package_constructor_args})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary'->'package_constructor_args' is not a reference to an array}; 
            }
            if($_->{default_dictionary}->{file} && !$NON_EMPTY_STRING->check($_->{default_dictionary}->{file})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary'->'file' is not a file path}; 
            }
            
            # make sure there is exactly 1 dictionary source defined
            unless($_->{default_dictionary}->{package} || $_->{default_dictionary}->{file}){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary' does not specify 'package' or 'file'};
            }
            if($_->{default_dictionary}->{package} && $_->{default_dictionary}->{file}){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_dictionary' specifies both 'package' and 'file'};
            }
        }
        
        # if defined, make sure the default rng is valid
        if($_->{default_rng}){
            # make sure it is a hashref
            unless(HashRef->check($_->{default_rng})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because it defines the key 'default_rng', but not as a reference to a hash};
            }
            
            # make sure there are no invalid keys
            my @invalid_rng_keys = ();
            foreach my $key (sort keys %{$_->{default_rng}}){
                unless($key =~ m/^(?:package)|(?:package_constructor_args)$/sx){
                    push @invalid_rng_keys, $key;
                }
            }
            if(scalar @invalid_rng_keys){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_rng' is indexed by one or more invalid keys: }.(join q{, }, @invalid_rng_keys);
            }
            
            # make sure each key is valid
            if($_->{default_rng}->{package} && !$PERL_PACKAGE_NAME->check($_->{default_rng}->{package})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_rng'->'package' is not a valid Perl package name}; 
            }
            if($_->{default_rng}->{package_constructor_args} && !ArrayRef->check($_->{default_rng}->{package_constructor_args})){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_rng'->'package_constructor_args' is not a reference to an array}; 
            }
            
            # make sure there is a package specified
            unless($_->{default_rng}->{package}){
                return var_to_string($_).q{ is not a valid hsxkpasswdrc file data structure because 'default_rng' does not specify a 'package'};  
            }
        }
        
        # a final return, in case none of the other more detailed messages were triggered
        return $basic_msg;
    },
    my_methods => {
        english => sub {return $RCFILE_DATA_ENGLISH;},
    },
);
__PACKAGE__->meta->add_type($RCFILE_DATA);

#
# === Finalise the Defined Types ==============================================#
#

# make the defined types immutable
__PACKAGE__->meta->make_immutable;

#
# === Public functions ========================================================#
#

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : Stringify any $ variable in a sane way
# Returns    : A string
# Arguments  : 1) the variable to render
# Throws     : NOTHING
# Notes      :
# See Also   :
sub var_to_string{
    my $var = shift;
    
    # deal with undef
    unless(defined $var){
        return 'Undef';
    }
    
    # find out if the variable is a referece
    my $ref = ref $var;
    
    # deal with a non-reference (i.e a plain scalars)
    unless($ref){
        return "Value '$var'";
    }
    
    # deal with each possible reference type
    if($ref eq 'SCALAR'){
        my $val = ${$var};
        unless($val){
            return 'Reference to EmptyString';
        }
        return "Reference to '$val'";
    }elsif($ref eq 'ARRAY' || $ref eq 'HASH'){
        # use data dumper to stringify the reference
        my $dd = Data::Dumper->new([$var]);
        $dd->Indent(0)->Useqq(1)->Terse(1)->Sortkeys(1)->Maxdepth(2); ## no critic (ProhibitLongChainsOfMethodCalls)
        my $var_str = $dd->Dump();
        
        # truncate the stringified reference if needed
        my $max_length = 72;
        if(length $var_str > $max_length){
            $var_str = (substr $var_str, 0, $max_length - 12).'...'.(substr $var_str, -1, 1);
        }
        
        # return the final string
        return 'Reference to '.$var_str;
    }else{
        return "Reference to $ref";
    }
}

#
# === 'Private' helper functions ==============================================#
#

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : Expose direct access to $_KEYS for classes in the
#              Crypt::HSXKPasswd package
# Returns    : A hashref
# Arguments  : NONE
# Throws     : NOTHING
# Notes      : This function is private so it should not be used by any 3rd
#              party devs - Use the public function
#              Crypt::HSXKPasswd->config_key_definitions() instead!
# See Also   : Crypt::HSXKPasswd->config_key_definitions()
sub _config_keys{ ## no critic (ProhibitUnusedPrivateSubroutines)
    return $_KEYS;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : Expose direct access to $_PRESETS for classes in the
#              Crypt::HSXKPasswd package
# Returns    : A hashref
# Arguments  : NONE
# Throws     : NOTHING
# Notes      : This function is private so it should not be used by any 3rd
#              party devs - Use the public function
#              Crypt::HSXKPasswd->preset_definitions() instead!
# See Also   : Crypt::HSXKPasswd->preset_definitions()
sub _presets{ ## no critic (ProhibitUnusedPrivateSubroutines)
    return $_PRESETS;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Generate the error message for a config key
# Returns    : a string
# Arguments  : 1) the invalid value
#              2) the name of the config key
#              3) a description of the expected value
# Throws     : NOTHING
# Notes      :
# See Also   :
sub _config_key_message{
    my $val = shift;
    my $key = shift;
    my $exp = shift;
    return var_to_string($val).qq{ is not a valid value for the config key '$key' - must be $exp};
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Extract invalid key names from a hashref
# Returns    : An array of strings, potentially of length 0
# Arguments  : 1) a reference to a hash validated against HashRef
# Throws     : NOTHING
# Notes      : If invalid args are received, an empty array is returned.
#              Validation against HashRef is assumed, and not re-tested.
# See Also   :
sub _extract_invalid_key_names{
    my $hashref = shift;
    
    # validate args
    unless(defined $hashref && ref $hashref eq 'HASH'){
        return ();
    }
    
    # check each key in the hash and return all that are not valid config key names
    my @invaid_keys = ();
    foreach my $key (keys %{$hashref}){
        unless($CONFIG_KEY_NAME->check($key)){
            push @invaid_keys, $key;
        }
    }
    return @invaid_keys;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : Extract keys with invalid values from a hashref
# Returns    : An array of strings, potentially of length 0
# Arguments  : 1) a reference to a hash where every key has been validated
#                 against ConfigKeyName.
# Throws     : NOTHING
# Notes      : If invalid args are received, an empty array is returned.
#              Validation of the keys is assumed and not re-tested.
# See Also   :
sub _extract_invalid_valued_keys{
    my $hashref = shift;
    
    # validate args
    unless(defined $hashref && ref $hashref eq 'HASH'){
        return ();
    }
    
    # check each value in the hash and return the keys for all that are not valid
    my @invaid_valued_keys = ();
    foreach my $key (keys %{$hashref}){
        unless($CONFIG_KEY_ASSIGNMENT->check({$key => $hashref->{$key}})){
            push @invaid_valued_keys, $key;
        }
    }
    return @invaid_valued_keys;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Return a list of required config keys not defined in a hashref
# Returns    : An array of strings
# Arguments  : 1) a reference to a hashref that has been validated against
#                 ConfigOverrides
# Throws     : NOTHIG
# Notes      : If invalid args are received, an empty array is returned.
#              Validation against ConfigOverrides is assumed and not re-tested.
# See Also   :
sub _extract_missing_required_keys{
    my $hashref = shift;
    
    # validate args
    unless(defined $hashref && ref $hashref eq 'HASH'){
        return ();
    }
    
    # check that each required key is present
    my @missing_keys = ();
    CONFIG_KEY:
    foreach my $key (keys %{$_KEYS}){
        # skip keys that are not required
        next CONFIG_KEY unless $_KEYS->{$key}->{required};
        
        # check the required key is present, and if not, save that fact
        unless(defined $hashref->{$key}){
            push @missing_keys, $key;
        }
    }
    
    # return the list of missing keys
    return @missing_keys;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE)
# Purpose    : Return a list of unfulfilled config key interdependencies
# Returns    : An array of strings
# Arguments  : 1) a reference to a hashref that has been validated against
#                 ConfigOverrides
# Throws     : NOTHING
# Notes      : If invalid args are received, an empty array is returned.
#              Validation against ConfigOverrides is assumed and not re-tested.
# See Also   :
sub _extract_unfulfilled_key_interdependencies{
    my $hashref = shift;
    
    # validate args
    unless(defined $hashref && ref $hashref eq 'HASH'){
        return ();
    }
    
    # check that all key interrelationships are valid
    my @unfulfilled_key_interdependencies = ();
    
    # if there is a need for a symbol alphabet, make sure one is defined
    if($hashref->{separator_character} eq 'RANDOM'){
        unless(defined $hashref->{symbol_alphabet} || defined $hashref->{separator_alphabet}){
            push @unfulfilled_key_interdependencies, q{when the config key 'separator_character' is set to 'RANDOM', a symbol alphabet must be specified with one of the config keys 'symbol_alphabet' or 'separator_alphabet'};
        }
    }
    
    # if there is any kind of character padding, make sure a cromulent padding character is specified
    if($hashref->{padding_type} ne 'NONE'){
        unless(defined $hashref->{padding_character}){
            push @unfulfilled_key_interdependencies, q{when the config key 'padding_type' is not set to 'NONE', the config key 'padding_character' must be set};
        }
        if($hashref->{padding_character} eq 'RANDOM'){
            unless(defined $hashref->{symbol_alphabet} || defined $hashref->{padding_alphabet}){
                push @unfulfilled_key_interdependencies, q{when the config key 'padding_character' is set to 'RANDOM', a symbol alphabet must be specified with one of the config keys 'symbol_alphabet' or 'padding_alphabet'};
            }
        }
        if($hashref->{padding_character} eq 'SEPARATOR' && $hashref->{separator_character} eq 'NONE'){
            push @unfulfilled_key_interdependencies, q{the config key 'padding_character' cannot be set 'SEPARATOR' when the config key 'separator_character' is set to 'NONE'};
        }
    }
    
    # if there is fixed character padding, make sure before and after are specified, and at least one has a value greater than 1
    if($hashref->{padding_type} eq 'FIXED'){
        unless(defined $hashref->{padding_characters_before} && defined $hashref->{padding_characters_after}){
            push @unfulfilled_key_interdependencies, q{when the config key 'padding_type' is set to 'FIXED', both the config keys 'padding_characters_before' and 'padding_characters_after' must be set};
        }
        unless($hashref->{padding_characters_before} + $hashref->{padding_characters_after} > 0){
            push @unfulfilled_key_interdependencies, q{when the config key 'padding_type' is set to 'FIXED', at least one of the config keys 'padding_characters_before' and 'padding_characters_after' must be set to a value greater than 1. (to specify that no symbol padding should be used, set the config key 'padding_type' to 'NONE')};
        }
    }
    
    # if there is adaptive padding, make sure a length is specified
    if($hashref->{padding_type} eq 'ADAPTIVE'){
        unless(defined $hashref->{pad_to_length}){
            push @unfulfilled_key_interdependencies, q{when the config key 'padding_type' is set to 'ADAPTIVE', the config key 'pad_to_length' must be set};
        }
    }
    
    # return the list of unfullfilled requirements
    return @unfulfilled_key_interdependencies;
}

1; # because perl is a tad odd :)
