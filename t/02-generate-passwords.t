#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Share qw( :all ); # for accessing the dictionary files in share
use Crypt::HSXKPasswd;
use Crypt::HSXKPasswd::Dictionary::EN;
use Crypt::HSXKPasswd::RNG::Basic;

plan tests => 10;

# supress entropy warnings - some of the test data will be very low in entropy!
Crypt::HSXKPasswd->module_config('ENTROPY_WARNINGS', 'NONE');

#
# generate a password with each of the named arguents in the constructor
#
ok(eval{hsxkpasswd()}, 'password generation with defaults');
ok(
    eval{
        my $dictionary = Crypt::HSXKPasswd::Dictionary::EN->new();
        hsxkpasswd(dictionary => $dictionary);
    },
    q{password generation with named argument 'dictionary'},
);
ok(
    eval{
        my $word_list = [qw(some test words)];
        hsxkpasswd(dictionary_list => $word_list);
    },
    q{password generation with named argument 'dictionary_list'},
);
ok(
    eval{
        hsxkpasswd(dictionary_file => dist_file('Crypt-HSXKPasswd', 'sample_dict_EN.txt'));
    },
    q{password generation with named argument 'dictionary_file'},
);
ok(
    eval{
        hsxkpasswd(
            dictionary_file => dist_file('Crypt-HSXKPasswd', 'sample_dict_EN.txt'),
            dictionary_file_encoding => 'utf-8',
        );
    },
    q{password generation with named arguments 'dictionary_file' & 'dictionary_file_encoding'},
);
ok(
    eval{
        my $config = Crypt::HSXKPasswd->preset_config('XKCD');
        hsxkpasswd(config => $config);
    },
    q{password generation with named argument 'config'},
);
SKIP: {
    skip 'JSON not installed', 1 unless eval{ require JSON; } || 0;
    
    ok(
        eval{
            my $config = Crypt::HSXKPasswd->config_to_json(Crypt::HSXKPasswd->preset_config('XKCD'));
            hsxkpasswd(config_json => $config);
        },
        q{password generation with named argument 'config_json'},
    );
    
}
ok(
    eval{
        hsxkpasswd(preset => 'XKCD');
    },
    q{password generation with named argument 'preset'},
);
ok(
    eval{
        hsxkpasswd(
            preset => 'XKCD',
            preset_overrides => {separator_character => '+'},
        );
    },
    q{password generation with named arguments 'preset' & 'preset_overrides'},
);
ok(
    eval{
        my $rng = Crypt::HSXKPasswd::RNG::Basic->new();
        hsxkpasswd(rng => $rng);
    },
    q{password generation with named argument 'preset'},
);