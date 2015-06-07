#!perl
use 5.006;
use strict;
use warnings;
use Test::More;
use File::Spec; # for accessing the perlcritic rc file
use English qw(-no_match_vars);

if(not $ENV{TEST_AUTHOR}) {
    my $msg = 'Author test.  Set $ENV{TEST_AUTHOR} to a true value to run.';
    plan(skip_all => $msg);
}

eval{ require Test::Perl::Critic; };

if($EVAL_ERROR){
    my $msg = 'Test::Perl::Critic required to criticise code';
    plan( skip_all => $msg );
}

my $rcfile = File::Spec->catfile('t', 'perlcriticrc');
Test::Perl::Critic->import(-profile => $rcfile);
  
# for now, don't test everything because the large dictionaries really screw things up
#all_critic_ok();
  
# test specified files
all_critic_ok(
    'blib/lib/Crypt/HSXKPasswd/Dictionary/Basic.pm',
    'blib/lib/Crypt/HSXKPasswd/Dictionary/EN.pm',
    'blib/lib/Crypt/HSXKPasswd/Dictionary/System.pm',
    'blib/lib/Crypt/HSXKPasswd/Dictionary.pm',
    'blib/lib/Crypt/HSXKPasswd/Helper.pm',
    'blib/lib/Crypt/HSXKPasswd/RNG',
    'blib/lib/Crypt/HSXKPasswd/RNG.pm',
    'blib/lib/Crypt/HSXKPasswd/Types.pm',
    'blib/lib/Crypt/HSXKPasswd/Util.pm',
    'blib/lib/Crypt/HSXKPasswd.pm',
    'blib/script/hsxkpasswd',
);