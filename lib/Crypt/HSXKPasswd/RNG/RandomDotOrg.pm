package Crypt::HSXKPasswd::RNG::RandomDotOrg;

use parent Crypt::HSXKPasswd::RNG;

# import required modules
use strict;
use warnings;
use Carp; # for nicer 'exception' handling for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions on failure
use English qw( -no_match_vars ); # for more readable code
use Readonly; # for truly constant constants
use Type::Tiny; # for creating anonymous type definitions
use Type::Params qw( compile ); # for parameter validation with Type::Tiny objects
use Types::Standard qw( :types slurpy ); # for standard types like Str and Int etc.
use Crypt::HSXKPasswd::Types qw( :types ); # for custom type checking
use Crypt::HSXKPasswd::Helper; # exports utility functions like _error & _warn

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

# import (or not) modules not listed as required by Crypt::HSXKPasswd
Readonly my $_CAN_EMAIL_VALID => eval{
    require Email::Valid; # for email address validation
} || 0;
Readonly my $_CAN_URI => eval{
    require URI; # for assembling the query to the random.org API
} || 0;
Readonly my $_CAN_LWP_UA => eval{
    require LWP::UserAgent; # for sending HTTP requests to the random.org API (requires Mozilla::CA be installed to work with HTTPS)
} || 0;
Readonly my $_CAN_HTTPS => eval{
    require Mozilla::CA; # without this module LWP::UserAgent can't do HTTPS
} || 0;
# if all the 'non-standard' modules (for want of a better term) were not loaded, croak
unless($_CAN_EMAIL_VALID && $_CAN_URI && $_CAN_LWP_UA && $_CAN_HTTPS){
    croak('Crypt::HSXKPasswd::RNG::RandomDotORg requires modules not required by any other classes in Crypt::HSXKPasswd, and one or more of them are not installed: Email::Valid, URI, LWP::UserAgent & Mozilla::CA');
}

# Copyright (c) 2015, Bart Busschots T/A Bartificer Web Solutions All rights
# reserved.
#
# Code released under the FreeBSD license (included in the POD at the bottom of
# HSXKPasswd.pm)

#
# --- Constants ---------------------------------------------------------------
#

# version info
use version; our $VERSION = qv('1.2');

# utility variables
Readonly my $_CLASS => __PACKAGE__;

# Random.org settings
Readonly my $RDO_URL => 'https://www.random.org/integers/';
Readonly my $RDO_MAX_INT => 100_000_000;

#
# --- Constructor -------------------------------------------------------------
#

#####-SUB-#####################################################################
# Type       : CONSTRUCTOR (CLASS)
# Returns    : An object of type Crypt::HSXKPasswd::RNG::RandomDotOrg
# Arguments  : 1) the email address to include in the web service calls (the
#                 TOS requests that this informaiton be included in the
#                 UserAgent string when making API requests.
#              2) OPTIONAL - named arguments:
#                 num_passwords - the number of passwords to fetch random
#                     numbers for at a time (a multiplier to apply to the
#                     argument received by random_numbers()), defaults to 3
#                 num_absolute - the absolute number of random numbers to fetch
#                     at a time. If specified, this value will take precidence
#                     over num_passwords
#                 timeout - the timeout (in seconds) for the HTTP request to
#                     the random.org web service (should be high according to
#                     TOS) - defaults to 180 seconds (3 minuites)
# Throws     : Croaks on invalid invocation and invalid args.
# Notes      : 
# See Also   : 
sub new{
    my @args = @_;
    my $class = shift @args;
    _force_class($class);
    
    # validate args
    state $args_check = compile(
        Type::Tiny->new(
            display_name => 'Email Address',
            parent => NonEmptyString,
            constraint => sub{
                return Email::Valid->address($_);
            },
        ),
        slurpy Dict[
            num_passwords => Optional[PositiveInteger],
            num_absolute => Optional[PositiveInteger],
            timeout => Optional[PositiveInteger],
        ],
    );
    my ($email, $options) = $args_check->(@args);
    
    # set defaults
    my $num_passwords = $options->{num_passwords} || 3;
    my $num_absolute = $options->{num_absolute} || 0;
    my $timeout = $options->{timeout} || 180;
    if($num_absolute){ # allow  num_absolute take prescedence
        $num_passwords = 0;
    }
    
    # initialise an object
    my $instance = {
        email => $email,
        timeout => $timeout,
        num_passwords => $num_passwords,
        num_absolute => $num_absolute,
    };
    bless $instance, $class;
    
    # return the object
    return $instance;
}

#
# --- Public Instance functions -----------------------------------------------
#

#####-SUB-#####################################################################
# Type       : INSTANCE
# Purpose    : Override the parent random_numbers() function and generate
#              random numbers between 0 and 1.
# Returns    : An array of numbers between 0 and 1
# Arguments  : 1) the number of random numbers needed to produce 1 password.
# Throws     : Croaks on error, carps if it receives invalid numbers from RDO
# Notes      : 
# See Also   :
sub random_numbers{
    my @args = @_;
    my $self = shift @args;
    _force_instance($self);
    
    # validate args
    state $args_check = compile(PositiveInteger);
    my ($num_per_password) = $args_check->(@args);
    
    # figure out how many numbers to request from the web service
    my $num = 0;
    if($self->{num_absolute}){
        $num = $self->{num_absolute};
    }else{
        $num = $num_per_password * $self->{num_passwords};
    }
    unless($num){
        _error('failed to determine how many passwords to request from the web service (this error should be impossible!)');
    }
    
    # generate the URL + query string
    my %query_params = (
        num => $num,
        min => 0,
        max => $RDO_MAX_INT,
        col => 1,
        base => 10,
        format => 'plain',
        rnd => 'new',
    );
    my $url = URI->new($RDO_URL);
    $url->query_form(%query_params);
    
    # assemble/prepare the web request
    my $ua = LWP::UserAgent->new();
    $ua->timeout($self->{timeout});
    $ua->agent($_CLASS.' (on behalf of '.$self->{email}.') ');
    
    # execute the web request
    my $response = $ua->get($url);
    if($response->is_error()){
        _error('failed to retrieve numbers from Random.Org web service with error code '.$response->code().' ('.$response->message.')');
    }
    
    # parse the result
    my $raw_numbers = $response->decoded_content();
    my @ans = ();
    RESPONSE_LINE:
    foreach my $line (split /\n/sx, $raw_numbers){
        # validate the line
        unless($line && $line =~ m/^\d+$/sx){
            _warn("received invalid number from Random.Org ($line)");
            next RESPONSE_LINE;
        }
        
        # convert from integer to decimal between 0 and 1
        my $dec = $line/$RDO_MAX_INT;
        unless($dec >= 0 && $dec <=1){
            _warn("failed to convert integer from from Random.Org to decimal between 0 and 1 ($line => $dec)");
            next RESPONSE_LINE;
        }
        
        # store the decimal
        push @ans, $dec;
    }
    unless(scalar @ans){
        _error('no valid random numbers found in response from Random.Org web service');
    }
    
    # return the random numbers
    return @ans;
}

1; # because Perl is just a little bit odd :)