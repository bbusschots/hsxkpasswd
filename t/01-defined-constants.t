#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;
use Crypt::HSXKPasswd;

plan tests => 2;

# check the config key definitions
ok(eval{Crypt::HSXKPasswd->_check_config_key_definitions()}, 'validate config key definitions');

# check the preset definitions
ok(eval{Crypt::HSXKPasswd->_check_preset_definitions()}, 'validate preset definitions');