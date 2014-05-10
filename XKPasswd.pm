package XKPasswd;

use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use English qw( -no_match_vars ); # for more readable code

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

# utility variables
my $_CLASS = 'XKPasswd';

#
# Constructor -----------------------------------------------------------------
#

#####-SUB-######################################################################
# Type       : CONSTRUCTOR (CLASS)
# Purpose    : Instantiate an object of type XKPasswd
# Returns    : An object of type XKPasswd
# Arguments  : 1. OPTIONAL - a configuration hashref
#              2. OPTIONAL - a true value to enter debug mode
# Throws     : Croaks if the function is called in an invalid way, or with an invalid config
# Notes      : For valid configuarion options see POD documentation below
# See Also   :
sub new{
    my $class = shift;
    my $config = shift;
    my $debug = shift;
    
    # validate args
    unless($class && $class eq $_CLASS){
        croak((caller 0)[3].'() - invalid invocation of constructor');
    }
    
    # initialise the object
    my $instance = {
        # 'public' instance variables
        debug => 0,
        # 'PRIVATE' internal variables
        _CONFIG => {},
        _CACHE_DICTIONARY_FULL => [], # a cache of all words found in the dictionary file
        _CACHE_DICTIONARY_LIMITED => [], # a cache of all the words found in the dictionary file that meet the length criteria
        _CACHE_RANDOM => [], # a cache of random numbers (as floating points between 0 and 1)
    };
    if($debug){
        $instance->{debug} = 1;
    }
    bless $instance, $class;
    
    # if no config was passed, use a default one
    unless($config){
        $config = default_config();
    }
    
    # load the config
    $instance->load_config($config);
    
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
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub default_config{
    # no need to check how this function was invoked, it just spits out a hashref
    return {
        dictionary_file_path => 'dict.txt', # defaults to a file called dict.txt in the current working directory
        symbol_alphabet => [qw{! @ $ % ^ & * - _ + = : | ~ ?}],
        word_length_min => 4,
        word_length_max => 8,
        separator_character => 'RANDOM',
        padding_digits_before => 2,
        padding_digits_after => 2,
        padding_type => 'FIXED',
        padding_character => 'RANDOM',
        padding_characters_before => 2,
        padding_characters_after => 2,
        case_transform => 'NONE',
    };
}

#####-SUB-######################################################################
# Type       : CLASS
# Purpose    : validate a config hashref
# Returns    : 1 if the config is valid, 0 otherwise
# Arguments  : 1. a hashref to validate
#              2. OPTIONAL - a true value to throw exception on error
# Throws     : Croaks on invalid args, or on error if second arg is truthy
# Notes      :
# See Also   :
## no critic (ProhibitExcessComplexity);
sub is_valid_config{
    my $class = shift;
    my $config = shift;
    my $carp = shift;
    
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
    
    # the dictionary
    unless($config->{dictionary_file_path} && -f $config->{dictionary_file_path}){
        croak('Invalid or missing dictionary_file_path - must a valid file path') if $carp;
        return 0;
    }
    
    # the symbol alphabet
    unless($config->{symbol_alphabet} && ref $config->{symbol_alphabet} eq 'ARRAY' && scalar $config->{symbol_alphabet} >= 5){
        croak('Invalid or missing symbol_alphabet - must be an array ref contianing at least 5 elements') if $carp;
        return 0;
    }
    
    # the word length restrictions
    unless($config->{word_length_min} && $config->{word_length_min} =~ m/^\d+$/sx && $config->{word_length_min} > 3){
        croak('Invalid or missing word_length_min - must be an integer greater than 3') if $carp;
        return 0;
    }
    unless($config->{word_length_max} && $config->{word_length_max} =~ m/^\d+$/sx && $config->{word_length_max} > 3){
        croak('Invalid or missing word_length_max - must be an integer greater than 3') if $carp;
        return 0;
    }
    if($config->{word_length_max} < $config->{word_length_min}){
        croak('word_length_max must be greater than or equal to word_length_min') if $carp;
        return 0;
    }
    
    # the separator character
    unless($config->{separator_character} && $config->{separator_character} =~ m/^[.]|(NONE)|(RANDOM)$/sx){
        croak(q{Invalid or missing separator_character - must be a single character, 'NONE' or 'RANDOM'}) if $carp;
        return 0;
    }
    
    # padding digits
    unless(defined $config->{padding_digits_before} && $config->{padding_digits_before} =~ m/^\d+$/sx){
        croak('Invalid or missing padding_digits_before - must be an integer greater than or equal to 0') if $carp;
        return 0;
    }
    unless(defined $config->{padding_digits_after} && $config->{padding_digits_after} =~ m/^\d+$/sx){
        croak('Invalid or missing padding_digits_after - must be an integer greater than or equal to 0') if $carp;
        return 0;
    }
    
    # padding characters
    unless($config->{padding_type} && $config->{padding_type} =~ m/^(NONE)|(FIXED)|(ADAPTIVE)$/sx){
        croak(q{Invalid or missing padding_type - must be 'NONE', 'FIXED', or 'ADAPTIVE'}) if $carp;
        return 0;
    }
    if($config->{padding_type} eq 'FIXED'){
        unless($config->{padding_characters_before} && $config->{padding_characters_before} =~ m/^\d+$/sx && $config->{padding_characters_before} > 1){
            croak(q{Invalid or missing padding_characters_before (required by padding_type='FIXED') - must be a positive integer}) if $carp;
            return 0;
        }
        unless($config->{padding_characters_after} && $config->{padding_characters_after} =~ m/^\d+$/sx && $config->{padding_characters_after} > 1){
            croak(q{Invalid or missing padding_characters_after (required by padding_type='FIXED') - must be a positive integer}) if $carp;
            return 0;
        }
    }elsif($config->{padding_type} eq 'ADAPTIVE'){
        unless($config->{pad_to_length} && $config->{pad_to_length} =~ m/^\d+$/sx && $config->{pad_to_length} >= 12){
            croak(q{Invalid or missing pad_to_length (required by padding_type='ADAPTIVE') - must be an integer greater than or equal to 12}) if $carp;
            return 0;
        }
    }
    if($config->{padding_type} eq 'FIXED' || $config->{padding_type} eq 'ADAPTIVE'){
        unless($config->{padding_character} && $config->{padding_character} =~ m/^[.]|(NONE)|(RANDOM)$/sx){
            croak(q{Invalid or missing padding_character - must be a single character, 'NONE' or 'RANDOM'}) if $carp;
            return 0;
        }
    }
    
    # case transformations
    unless($config->{case_transform} && $config->{case_transform} =~ m/^(NONE)|(UPPER)|(LOWER)|(CAPITALISE)|(INVERSE)|(RANDOM)$/sx){
        croak(q{Invalid or missing case_transform - must be 'NONE', 'UPPER', 'LOWER', 'CAPITALISE', 'INVERSE', or 'RANDOM'}) if $carp;
        return 0;
    }
    
    # if we got this far, all is well, so return true
    return 1;
}
## use critic

#
# Public Instance functions ---------------------------------------------------
#

#####-SUB-######################################################################
# Type       : INSTANCE
# Purpose    : Load a configuration hashref into the instance
# Returns    : The instance - to facilitate function chaining
# Arguments  : 1. a configuartion hashref
# Throws     : Croaks if the function is called in an invalid way, with invalid
#              arguments, or with an invalid config
# Notes      : For valid configuarion options see POD documentation below
# See Also   :
sub load_config{
    my $self = shift;
    my $config = shift;
    
    # validate args
    unless($self && $self->isa($_CLASS) && $config){
        croak((caller 0)[3].'() - invalid arguments - no source passed');
    }
    unless($config && ref $config eq 'HASH'){
        croak((caller 0)[3].'() - invalid arguments - must pass the config as a hashref');
    }
    eval{
        $_CLASS->is_valid_config($config, 1); # returns 1 if valid
    }or do{
        my $msg = (caller 0)[3].'() - invoked with invalid hashref';
        if($self->{debug}){
            $msg .= " ($EVAL_ERROR)";
        }
        croak($msg);
    };
    
    # save the config into the instance
    $self->{_CONFIG} = $config;
    
    # init the dictionary caches
    # TO DO
    
    # return a reference to self to facilitate function chaining
    return $self;
}

#
# 'Private' functions ---------------------------------------------------------
#


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

TO DO

=head2 CONFIGURATION HASHREFS

A number of subroutines require a configuration harshref as an argument. The
following are the valid keys for that hashref, what they mean, and what values
are valid for each.

=over 4

=item *

C<case_transform> - the alterations that should be made to the case of the
letters in the randomly chosen words that make up the bulk of the randomly
generated passwords. The following are the only valid values for this key:

=over 4

=item -

C<NONE> - the capitalisation used in the randomly generated password will be
the same as it is in the dictionary file.

=item -

C<UPPER> - all letters in all the words will be converted to upper case. B<Use
of this option is strongly discouraged for security reasons.>

=item -

C<LOWER> - all letters in all the words will be converted to lower case. B<Use
of this option is strongly discouraged for security reasons.>

=item -

C<CAPITALISE> - the first letter in every word will be converted to upper case,
all other letters will be converted to lower case.

=item -

C<INVERSE> - the first letter in every word will be converted to lower case,
all other letters will be converted to upper case.

=item -

C<RANDOM> - each word will be randomly converted to all upper case or all lower
case.

=back

=item *

C<dictionary_file_path> - a string containing the path to the dictionary file
to be used when generating passwords. The path must exist and point to a
regular file.

=item *

C<pad_to_length> - the total desired length of the password when using adaptive
padding (C<padding_type> set to C<ADAPTIVE>). The value must be a positive
integer greater than or equal to 12 (for security reasons).

=item *

C<padding_character> - the character to use when padding the front and/or back
of the randomly generated password. Acceptable values are a single character,
or, the special values C<NONE> (indicating that no separator should be used),
or C<RANDOM>, indicating that a character should be chosen at random from the
C<symbol_alphabet>. This key is only needed if C<padding_type> is set to
C<FIXED> or C<ADAPTIVE>.

=item *

C<padding_characters_before> & C<padding_characters_after> - the number of
symbols to pad the front and end of the randomly generated password with. The
values must be integers greater than or equal to zero. These keys are only
needed if C<padding_type> is set to C<FIXED>.

=item *

C<padding_digits_before> & C<padding_digits_after> - the number of random
digits to include before and after the randomly chosen words making up the bulk
of the randomly generated password. Values must be integers greater than or
equal to zero.

=item *

C<padding_type> - the type of symbol padding to be added at the start and/or
end of the randomly generated password. The only valid values for this key are
the following:

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

=item *

C<separator_character> - the character to use to separate the words in the
generated password. Acceptable values are a single character, or, the special
values C<NONE> (indicating that no separator should be used), or C<RANDOM>,
indicating that a character should be chosen at random from the
C<symbol_alphabet>.

=item *

C<symbol_alphabet> - an arrayref containing at least five single characters as
scalars. This alphabet will be used when selecting random characters to act as
the separator between words, or the padding at the start and/or end of
generated passwords.

=item *

C<word_length_min> & C<word_length_max> - the minimum and maximum length of the
words that will make up the generated password. The two keys can hold equal
values, but C<word_length_max> may not be smaller than C<word_length_min>. For
security reasons, both values must be greater than three.

=back

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