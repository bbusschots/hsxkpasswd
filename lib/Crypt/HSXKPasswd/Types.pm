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
# === Define The Fundamental Types ============================================#
#

# add a type for a single letter (a single alpha grapheme)
my $LETTER = Type::Tiny->new(
    name => 'Letter',
    parent => Str,
    constraint => sub{
        return $_ =~ m/^\pL$/sx;
    },
    message => sub{
        return _var_to_string($_).q{ is not a Letter (must be a string containing exactly one letter)};
    },
);
__PACKAGE__->meta->add_type($LETTER);

# add a type for words (a grouping of alpha characters at least four graphemes
# long)
my $WORD = Type::Tiny->new(
    name => 'Word',
    parent => Str,
    constraint => sub{
        return $_ =~ m/^\pL{4,}$/sx;
    },
    message => sub{
        return _var_to_string($_).q{ is not a Word (must be a string of only letters at least four long)};
    },
);
__PACKAGE__->meta->add_type($WORD);

# add a type for a single symbol (a single non-letter unicode grapheme)
my $SYMBOL = Type::Tiny->new(
    name => 'Symbol',
    parent => Str,
    constraint => sub{
        return $_ =~ m/^\X$/sx && $_ =~ m/^[^\pL]$/sx;
    },
    message => sub{
        return _var_to_string($_).q{ is not a Symbol (must be a string containing exactly one non-letter character)};
    },
);
__PACKAGE__->meta->add_type($SYMBOL);

# add a type for symbol alphabets - array refs containing only, and at least 2,
# single-character strings
my $SYMBOL_ALPHABET = Type::Tiny->new(
    name => 'SymbolAlphabet',
    parent => ArrayRef[$SYMBOL],
    constraint => sub{
        my @unique_symbols = uniq(@{$_});
        return scalar @unique_symbols >= 2;
    },
    message => sub{
        return _var_to_string($_).q{ is not a Symbol Alphabet (must be a reference to an array of distinct Symbols at least two long)};
    },
);
__PACKAGE__->meta->add_type($SYMBOL_ALPHABET);

# add a type for positive integers (including 0)
my $POSITIVE_INTEGER = Type::Tiny->new(
    name => 'PositiveInteger',
    parent => Int,
    constraint => sub{
        return $_ >= 0;
    },
    message => sub{
        return _var_to_string($_).q{ is not a Positive Integer};
    },
);
__PACKAGE__->meta->add_type($POSITIVE_INTEGER);

# add a type for word lengths - integers greater than 3
my $WORD_LENGTH = Type::Tiny->new(
    name => 'WordLength',
    parent => Int,
    constraint => sub{
        return $_ > 3;
    },
    message => sub{
        return _var_to_string($_).q{ is not a valid Word Length (must be an integer greater than 3)};
    },
);
__PACKAGE__->meta->add_type($WORD_LENGTH);

#
# === Define the Config Keys and Types ========================================#
#

my $_KEYS = {
    allow_accents => {
        req => 0,
        type => Value,
        desc => 'Any truthy or falsy scalar value',
    },
    symbol_alphabet => {
        req => 0,
        type => $SYMBOL_ALPHABET,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    separator_alphabet => {
        req => 0,
        type => $SYMBOL_ALPHABET,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    padding_alphabet => {
        req => 0,
        type => $SYMBOL_ALPHABET,
        desc => 'A reference to an array containing at least 2 distinct single-character strings',
    },
    word_length_min => {
        req => 1,
        type => $WORD_LENGTH,
        desc => 'An integer greater than three',
    },
    word_length_max => {
        req => 1,
        type => $WORD_LENGTH,
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
                return $SYMBOL->check($_) || $_ =~ m/^(NONE)|(RANDOM)$/sx;
            },
        ),
        desc => q{A single character or one of the special values: 'NONE' or 'RANDOM'},
    },
    padding_digits_before => {
        req => 1,
        type => $POSITIVE_INTEGER,
        desc => 'An integer greater than or equal to zero',
    },
    padding_digits_after => {
        req => 1,
        type => $POSITIVE_INTEGER,
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
        type => $POSITIVE_INTEGER,
        desc => 'An integer greater than or equal to one',
    },
    padding_characters_after => {
        req => 0,
        type => $POSITIVE_INTEGER,
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
                return $SYMBOL->check($_) || $_ =~ m/^(NONE)|(RANDOM)|(SEPARATOR)$/sx;
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
            parent => Map[$LETTER, Str],
        ),
        desc => 'A hash ref mapping letters to their replacements - can be empty',
    },
};

# add a type for config key names
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
);
__PACKAGE__->meta->add_type($CONFIG_KEY_NAME);

# add a type for a config key name-value pair - must be a reference to a
# hash with exactly one key, which must be a valid config key, and the
# value accompanying that key must be valid for the given key
my $CONFIG_KEY = Type::Tiny->new(
    name => 'ConfigKey',
    parent => Map[$CONFIG_KEY_NAME, Defined],
    constraint => sub{
        # make sure there is exactly 1 key
        unless(scalar keys %{$_} == 1){
            return 0;
        }
        
        # extract the key and value
        my $key = (keys %{$_})[0];
        my $val = $_->{$key};
        
        # validate the value and return the result
        return Crypt::HSXKPasswd->_key_definitions()->{$key}->{type}->check($val);
    },
);
__PACKAGE__->meta->add_type($CONFIG_KEY);

# a type for config overrides
my $OVERRIDES = Type::Tiny->new(
    name => 'ConfigOverrides',
    parent => Map[$CONFIG_KEY_NAME, Defined],
    constraint => sub{
        my %test_hash = %{$_};
        
        # make sure at least one key is specified
        unless(scalar keys %test_hash){
            return 0;
        }
        
        # make sure each key specified maps to a valid value
        foreach my $key (keys %test_hash){
            unless($CONFIG_KEY->check({$key => $test_hash{$key}})){
                return 0;
            }
        }
        
        # if we got here, all is well, so return 1
        return 1;
    },
);
__PACKAGE__->meta->add_type($OVERRIDES);

# add a type for a valid config hashref
my $CONFIG = Type::Tiny->new(
    name => 'Config',
    parent => Map[$CONFIG_KEY_NAME, Defined],
    constraint => sub{
        return Crypt::HSXKPasswd->is_valid_config($_);
    },
);
__PACKAGE__->meta->add_type($CONFIG);

#
# === Finalise the Defined Types ==============================================#
#

# make the defined types immutable
__PACKAGE__->meta->make_immutable;

#
# === Public functions ========================================================#
#

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
sub _key_definitions{
    return $_KEYS;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE
# Purpose    : Stringify any $ variable in a sane way
# Returns    : A string
# Arguments  : 1) the variable to render
# Throws     : NOTHING
# Notes      :
# See Also   :
sub _var_to_string{
    my $var = shift;
    
    # deal with undef
    unless(defined $var){
        return 'Undef';
    }
    
    # find out if the variable is a referece
    my $ref = ref $var;
    
    # deal with a non-reference (i.e a plain scalars)
    unless($ref){
        unless($var){
            return 'EmptyString';
        }
        return "'$var'";
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
        $dd->Indent(0)->Useqq(1)->Terse(1)->Sortkeys(1)->Maxdepth(2);
        my $var_str = $dd->Dump();
        
        # truncate the stringified reference if needed
        my $max_length = 72;
        if(length $var_str > $max_length){
            $var_str = substr($var_str, 0, $max_length - 12).'...'.substr($var_str, -1, 1);
        }
        
        # return the final string
        return 'Reference to '.$var_str;
    }else{
        return "Reference to $ref";
    }
}

1; # because perl is a tad odd :)