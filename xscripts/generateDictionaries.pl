#!/usr/bin/perl

use strict;
use warnings;
use English qw( -no_match_vars );
use Fatal qw( :void open close binmode ); # make builtins throw exceptions
use Readonly; # for truly constant constants

# HSXKPasswd Stuff
use lib './lib/';
use Crypt::HSXKPasswd::Util;

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

my $description = <<'ENDDESC';
#==============================================================================#
# Build The Bundled Dictionaries for Crypt::HSXKPasswd
#==============================================================================#
#
# This script is stored in xscripts, but designed to be run from the root of the
# project.
#
# The key in the dictionaries hashref will become the leaf of the package name,
# pre-fixed by Crypt::HSXKPasswd::Dictionary::.
#
# The values in the dictionaries hashref should be file names in the project's
# share folder.
#
#==============================================================================#
ENDDESC

#
# === Constants ===============================================================#
#

# version info
use version; our $VERSION = qv('1.0_1');

# the pre-fix to put before the package name (WITH trailing ::)
Readonly my $PKG_PREFIX => 'Crypt::HSXKPasswd::Dictionary::';

# path to the folder with the dictionary text files (WITH trailing /)
Readonly my $DICT_TXT_FOLDER => './share/';

# the path to the folder where the .pm files should be saved (WITH trailing /)
Readonly my $PM_FOLDER => './lib/Crypt/HSXKPasswd/Dictionary/';

# define the dictionaries to create
Readonly my %DICTIONARIES => (
    DE => 'sample_dict_DE.txt',
    EN => 'sample_dict_EN.txt',
    ES => 'sample_dict_ES.txt',
    FR => 'sample_dict_FR.txt',
    IT => 'sample_dict_IT.txt',
    NL => 'sample_dict_NL.txt',
    PT => 'sample_dict_PT.txt',
);

#
# === Generate the Dictionaries ===============================================#
#

# loop through the defined dictionaries, and create them
foreach my $dict (sort keys %DICTIONARIES){
    # generate the code
    my $pkg = $PKG_PREFIX.$dict;
    my $source = $DICT_TXT_FOLDER.$DICTIONARIES{$dict};
    my $code = Crypt::HSXKPasswd::Util->dictionary_from_text_file($pkg, $source, 'UTF-8');
    
    # write it to the output file
    my $pm_path = $PM_FOLDER.$dict.q{.pm};
    say "INFO - Creating $pkg from $source, saving to $pm_path";
    open my $PM_FH, '>', $pm_path or croak("FATAL - failed to open $pm_path with error: $OS_ERROR");
    binmode $PM_FH, ':encoding(UTF-8)';
    print {$PM_FH} "$code\n";
    close $PM_FH;
}

say "\nDONE!";