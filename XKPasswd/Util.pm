package XKPasswd::Util;

use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code
use lib '../'; # to keep Komodo edit happy while programming
use XKPasswd;

# Copyright (c) 2014, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# ../XKPasswd.pm)

#
# === NOTE=====================================================================
# This module is not needed to use XKPasswd.pm, it merely contains utility
# functions that are useful during development.
#

#==============================================================================
# Code
#==============================================================================

#
# 'Constants'------------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.1_01');

# utility variables
my $_CLASS = 'XKPasswd::Util';

#
# Public Class (Static) functions ---------------------------------------------
#

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Test all presets defined in the XKPasswd module for validity and
#              against a given dictionary file for sufficient enthropy
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. the path to a dictionary file
# Throws     : Croaks on invalid invocation or args, or if there is a problem
#              testing the configs
# Notes      :
# See Also   :
sub test_presets{
    my $class = shift;
    my $dict_path = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $dict_path && -f $dict_path){
        XKPasswd->_error('invalid args, must pass a dictionary file path');
    }
    
    # get the list of config names from the parent
    my @preset_names = XKPasswd->defined_presets();
    print 'INFO - found '.(scalar @preset_names).' presets ('.(join q{, }, @preset_names).")\n";
    
    # first test the validity of all preset configs
    print "\nINFO - testing preset config validity\n";
    XKPasswd->_check_presets();
    print "INFO - Done testing config validity\n";
    
    # then test each config for sufficient entropy by instantiating an instance with each one
    print "\nINFO - testing preset config + dictionary entropy\n";
    foreach my $preset (@preset_names){
        print "Testing '$preset'\n";
        my $xkpasswd = XKPasswd->new($dict_path, $preset);
        my %stats = $xkpasswd->stats();
        print "$preset: TOTAL WORDS=$stats{dictionary_words_total}, AVAILABLE WORDS=$stats{dictionary_words_filtered} ($stats{dictionary_words_percent_avaialable}%)";
        print 'RESTRICTIONS: ';
        if($stats{dictionary_filter_length_min} == $stats{dictionary_filter_length_max}){
            print "length=$stats{dictionary_filter_length_min}\n";
        }else{
            print "$stats{dictionary_filter_length_min}>=length<=$stats{dictionary_filter_length_max}\n";
        }
        print "$preset: BLIND=$stats{password_entropy_blind_min} (need $XKPasswd::ENTROPY_MIN_BLIND), SEEN=$stats{password_entropy_seen} (need $XKPasswd::ENTROPY_MIN_SEEN)\n";
    }
    print "INFO - Done testing entropy\n";
    
    # to keep perlcritic happy
    return 1;
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : Generate a sample password with each preset with a given
#              dictionary file
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : NONE
# Throws     : Croaks on invalid invocation
# Notes      :
# See Also   :
sub print_preset_samples{
    my $class = shift;
    my $dict_path = shift;
    
    # validate the args
    unless(defined $class && $class eq $_CLASS){
        XKPasswd->_error('invalid invocation of class method');
    }
    unless(defined $dict_path && -f $dict_path){
        XKPasswd->_error('invalid args, must pass a dictionary file path');
    }
    
    foreach my $preset (XKPasswd->defined_presets()){
        print "$preset: ".xkpasswd($dict_path, $preset)."\n";
    }
    
    # to keep perlcritic happy
    return 1;
}

1; # because perl is a bit special