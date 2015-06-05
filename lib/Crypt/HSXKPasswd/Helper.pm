package Crypt::HSXKPasswd::Helper;

# import required modules
use strict;
use warnings;
use English qw( -no_match_vars );
use Carp; # for nicer 'exceptions' for users of the module
use Fatal qw( :void open close binmode ); # make builtins throw exceptions
use Scalar::Util qw( blessed ); # for checking if a reference is blessed
use List::MoreUtils qw( uniq ); # for array deduplication
use Readonly; # for truly constant constants
use Types::Standard qw( ClassName ); # needed for _force_class

# set things up for using UTF-8
use 5.016; # min Perl for good UTF-8 support, implies feature 'unicode_strings'
use Encode qw(encode decode);
use utf8;
binmode STDOUT, ':encoding(UTF-8)';

## no critic (ProhibitAutomaticExportation);
use base qw( Exporter );
our @EXPORT = qw( _do_debug _debug _warn _error _force_class _force_instance );
## use critic

# import (or not) optional modules
our $_CAN_STACK_TRACE = eval{
    require Devel::StackTrace; # for better error reporting when debugging
};

#==============================================================================#
# A helper class implemented shared functionality
#==============================================================================#
#
# All classes in the Crypt::HSXKPasswd package should inherit from this one as
# it provides basic functionality like error reporting.
#
#==============================================================================#

#
# === CONSTANTS & Package Vars ================================================#
#

# version info
use version; our $VERSION = qv('1.0');

# utility variables
Readonly my $_CLASS => __PACKAGE__;
Readonly my $BASE_PACKAGE => 'Crypt::HSXKPasswd';

# Debug and logging configuration
our $_LOG_STREAM = *STDERR; # default to logging to STDERR
our $_LOG_ERRORS = 0; # default to not logging errors
our $_DEBUG = 0; # default to not having debugging enabled

# Declare Package-level variable needed to control Carp
our @CARP_NOT;

#
# === 'Private' Functions to be Exported ======================================#
#

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Return 1 if we are in debug mode, and 0 otherwise.
# Returns    : 1 or 0
# Arguments  : NONE
# Throws     : NOTHING
# Notes      :
# See Also   :
sub _do_debug{ ## no critic (ProhibitUnusedPrivateSubroutines)
    return $_DEBUG ? 1 : 0;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Function for printing a debug message
# Returns    : Always return 1 (to keep perlcritic happpy)
# Arguments  : 1. the debug message to log
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for __log() which invokes that function with a severity
#              of 'DEBUG'
# See Also   : __log()
sub _debug{ ## no critic (ProhibitUnusedPrivateSubroutines)
    my $message = shift;
    my $stack_increment = shift;
    
    #pass the call on to __log
    return __log('DEBUG', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Function for issuing a warning
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the warning message to log
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for __log() which invokes that function with a severity
#              of 'WARNING'
# See Also   : __log()
sub _warn{ ## no critic (ProhibitUnusedPrivateSubroutines)
    my $message = shift;
    my $stack_increment = shift;
    
    #pass the call on to __log
    return __log('WARNING', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Function for throwing an error
# Returns    : Always returns 1 to keep perlcritic happy
# Arguments  : 1. the error message to log
#              2. OPTIONAL - a number of function calls to hide from users in
#                 the output.
# Throws     : Croaks on invalid invocation
# Notes      : a wrapper for __log() which invokes that function with a severity
#              of 'ERROR'
# See Also   : __log()
sub _error{
    my $message = shift;
    my $stack_increment = shift;
    
    #pass the call on to __log
    return __log('ERROR', $message, $stack_increment);
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Test the $class in a class function to make sure it was actually
#              invoked on the correct class.
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1) the $class variable to test
# Throws     : Croaks if $class is not valid
# Notes      :
# See Also   :
sub _force_class{ ## no critic (ProhibitUnusedPrivateSubroutines)
    my $test_class = shift;
    
    # find the package hosting the call to _force_class
    my $host_class = __calling_package();
    unless($host_class){
        _error(q{failed to determine package hosting the funciton who's invocation should be tested});
    }
    
    # test the class
    unless(ClassName->check($test_class)){
        # try get the data needed to get the bare function name
        my $calling_sub = (caller 1)[3];
        
        if($calling_sub){
            # print a nicer error message
            $calling_sub =~ s/^$host_class[:]{2}//sx; # strip the package name from the sub
            _error('invalid invocation - must be invoked on the class, e.g. '.$host_class.q{->}.$calling_sub.q{() - invocation on child classes also OK}, 1);
        }else{
            # fall back to the less nice output
            _error("invalid invocation - must be invoked on the class $host_class (or on a child class)", 1);
        }
    }
    
    return 1;
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (PRIVATE) - EXPORTED
# Purpose    : Test the $self in an instance function to make sure it was
#              actually invoked as an instance function.
# Returns    : Always  returns 1 (to keep PerlCritic happy)
# Arguments  : 1) the $self variable to test
# Throws     : Croaks if the $self variable is not an instance of this class.
# Notes      :
# See Also   :
sub _force_instance{ ## no critic (ProhibitUnusedPrivateSubroutines)
    my $test_self = shift;
    
    # test against the direct caller
    my $required_package = __calling_package();
    unless(defined $test_self && blessed($test_self) && $test_self->isa($required_package)){
        _error("invalid invocation - must be invoked on an instance of $required_package", 1);
    }
    
    return 1;
}

#
# === VERY Private Functions (not exported) ===================================#
#

#####-SUB-######################################################################
# Type       : SUBROUTINE (VERY PRIVATE)
# Purpose    : A helper function to determine the package directly calling the
#              caller of this function.
# Returns    : A package name as a string.
# Arguments  : NONE
# Throws     : NOTHING
# Notes      : This function should only EVER be called from one of the exported
#              helper functions.
# See Also   :
sub __calling_package{
    return (caller 1)[0];
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (VERY PRIVATE)
# Purpose    : A helper function to return an array of all calling packages that
#              are within Crypt::HSXKPasswd (not including this package itself).
# Returns    : An array of strings which may be empty
# Arguments  : NONE
# Throws     : NOTHING
# Notes      : This function continues up the caller tree as long as it finds
#              that the calling package is within Crypt::HSXKPassd, then it
#              stops and returns.
# See Also   :
sub __interal_calling_packages{
    my @internal_packages = ();
    
    # loop through the caller tree until we go outside the base package
    my $i = 0;
    CALLER:
    while(caller $i){
        my $package = (caller $i)[0];
        
        # if there is no package defined, stop
        last CALLER unless $package;
        
        # check if the caller is internal or not
        if($package =~ m/^$BASE_PACKAGE/sx){
            # we are still internal, so save the package
            push @internal_packages, $package;
        }else{
            # we are external, so we are done
            last CALLER;
        }
        
        # move on to the next caller
        $i++;
    }
    
    # deduplicate the list & return
    return uniq(@internal_packages);
}

#####-SUB-######################################################################
# Type       : SUBROUTINE (VERY PRIVATE)
# Purpose    : Function to log output from the module - SHOULD NEVER BE CALLED
#              DIRECTLY
# Returns    : Always returns 1 (to keep perlcritic happy)
# Arguments  : 1. the severity of the message (one of 'DEBUG', 'WARNING', or
#                 'ERROR')
#              2. the message to log
#              3. OPTIONAL - an increment to add to the argument to caller - to
#                 allow functions like _force_instance to invisibly invoke
#                 _debug(), _warn() & _error().
# Throws     : Croaks on invalid invocation
# Notes      : THIS FUNCTION SHOULD NEVER BE CALLED DIRECTLY, but always called
#              via _debug(), _warn(), or _error().
#              This function does not croak on invalid args, it confess with as
#              useful an output as it can.
#              If the function prints output, it will do so to $LOG_STREAM. The
#              severity determines the functions exact behaviour:
#              * 'DEBUG' - message is always printed without a stack trace
#              * 'WARNING' - output is carped, and, if $LOG_ERRORS is true the
#                message is also printed
#              * 'ERROR' - output is confessed if $DEBUG and croaked otherwise.
#                If $LOG_ERRORS is true the message is also printed with a
#                stack trace (the stack trace is omited if Devel::StackTrace) is
#                not installed.
# See Also   : _debug(), _warn() & _error()
## no critic (ProhibitExcessComplexity);
sub __log{
    my $severity = uc shift;
    my $message = shift;
    my $stack_increment = shift;
    
    # before doing anything that could invoke a Carp function, get the list of
    # internal referrers, and set up @CARP_NOT
    # NOTE - the use of local is recommended in the Carp docs
    local @CARP_NOT = __interal_calling_packages(); ## no critic (ProhibitLocalVars);
    
    # validate the args
    unless(defined $severity && ref $severity eq q{} && length $severity > 1){
        $severity = 'UNKNOWN_SEVERITY';
    }
    unless(defined $message && ref $message eq q{}){
        my $output = 'ERROR - '.(caller 0)[3]."(): invoked with severity '$severity' without message at ".(caller 1)[1].q{:}.(caller 1)[2];
        if($_LOG_ERRORS){
            my $log_output = $output;
            if($_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
            }
            print {$_LOG_STREAM} $log_output."\n";
        }
        confess($output);
    }
    if(defined $stack_increment){
        unless(ref $stack_increment eq q{} && $stack_increment =~ m/^\d+$/sx){
            carp((caller 0)[3].'(): passed invalid stack increment - ignoring');
            $stack_increment = 0;
        }
    }else{
        $stack_increment = 0;
    }

    # figure out the correct index for the function that is really responsible
    my $caller_index = 2 + $stack_increment;
    my $calling_func = (caller 1)[3];
    unless($calling_func =~ m/^$_CLASS[:]{2}((_debug)|(_warn)|(_error))$/sx){
        print {$_LOG_STREAM} 'WARNING - '.(caller 0)[3].q{(): invoked directly rather than via _debug(), _warn() or _error() - DO NOT DO THIS!};
        $caller_index++;
    }

    # deal with evals
    my $true_caller = q{};
    my @caller = caller $caller_index;
    if(@caller){
        $true_caller = $caller[3];
    }
    my $eval_depth = 0;
    while($true_caller eq '(eval)'){
        $eval_depth++;
        $caller_index++;
        my @next_caller = caller $caller_index;
        if(@next_caller){
            $true_caller = $next_caller[3];
        }else{
            $true_caller = q{};
        }
    }
    if($true_caller eq q{}){
        $true_caller = 'UNKNOWN_FUNCTION';
    }

    # deal with the message as appropriate
    my $output = "$severity - ";
    if($eval_depth > 0){
        if($eval_depth == 1){
            $output .= "eval() within $true_caller";
        }else{
            $output .= "$eval_depth deep eval()s within $true_caller";
        }
    }else{
        $output .= $true_caller;
    }
    $output .= "(): $message";
    if($severity eq 'DEBUG'){
        # debugging, so always print and do nothing more
        print {$_LOG_STREAM} "$output\n" if $_DEBUG;
    }elsif($severity eq 'WARNING'){
        # warning - always carp, but first print if needed
        if($_LOG_ERRORS){
            print {$_LOG_STREAM} "$output\n";
        }
        carp($output);
    }elsif($severity eq 'ERROR'){
        # error - print if needed, then confess or croak depending on whether or not debugging
        if($_LOG_ERRORS){
            my $log_output = $output;
            if($_DEBUG && $_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
                print {$_LOG_STREAM} "$output\n";
            }
            print {$_LOG_STREAM} "$log_output\n";
        }
        if($_DEBUG){
            confess($output);
        }else{
            croak($output);
        }
    }else{
        # we have an unknown severity, so assume the worst and confess (also log if needed)
        if($_LOG_ERRORS){
            my $log_output = $output;
            if($_CAN_STACK_TRACE){
                $log_output .= "\nStack Trace:\n".Devel::StackTrace->new()->as_string();
            }
            print {$_LOG_STREAM} "$log_output\n";
        }
        confess($output);
    }
    
    # to keep perlcritic happy
    return 1;
}
## use critic

1; # because perl is a tad odd :)