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
use Type::Tiny;
use Types::Standard qw( :types );
use Crypt::HSXKPasswd; # for the config valiation function and key definitions

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
# === Define Types ============================================================#
#

# add a type for a single letter (a single alpha grapheme)
my $LETTER = Type::Tiny->new(
    name => 'Letter',
    parent => Str,
    constraint => sub{
        return $_ =~ m/^\pL$/sx;
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
);
__PACKAGE__->meta->add_type($WORD);

# add a type for a single symbol (a single unicode grapheme)
my $SYMBOL = Type::Tiny->new(
    name => 'Symbol',
    parent => Str,
    constraint => sub{
        return $_ =~ m/^\X$/sx;
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
);
__PACKAGE__->meta->add_type($SYMBOL_ALPHABET);

# add a type for positive integers (including 0)
my $POS_INT = Type::Tiny->new(
    name => 'PositiveInteger',
    parent => Int,
    constraint => sub{
        return $_ >= 0;
    },
);
__PACKAGE__->meta->add_type($POS_INT);

# add a type for config key names
my $CONFIG_KEY_NAME = Type::Tiny->new(
    name => 'ConfigKeyName',
    parent => Str,
    constraint => sub{
        my $test_val = $_;
        foreach my $key_name (Crypt::HSXKPasswd->defined_config_keys()){
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

# add a type for word lengths - integers greater than 3
my $WORD_LENGTH = Type::Tiny->new(
    name => 'WordLength',
    parent => Int,
    constraint => sub{
        return $_ > 3;
    },
);
__PACKAGE__->meta->add_type($WORD_LENGTH);

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

# make the defined types immutable
__PACKAGE__->meta->make_immutable;

1; # because perl is a tad odd :)