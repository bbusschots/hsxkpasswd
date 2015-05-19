xkpasswd.pm
===========

A Perl module for generating secure memorable passwords inspired by the Steve Gibson's Password Haystacks and the fabulous XKCD web comic. This is the library that drives www.xkpasswd.net

* Project Home Page: [www.bartb.ie/xkpasswd](http://www.bartb.ie/xkpasswd) - **please consider making a donation here**
* [Perl POD Documentation](http://bbusschots.github.io/xkpasswd.pm/pod.html)

This library is provided entirely free of charge under a very liberal free
licence. It has taken a signifficant amount of time to write, and continues to
take time to maintain and update. If you'd like to contribute towards that time
and effort, please consider making a donation at the project's home page (linked above).

Quick Install Guide
-------------------

This module has been packaged for distribution on CPAN, but has not yet been published there. It will appear there shortly.

In the mean time, it can be installed manually as follows (from the root of the GIT project as root):

    perl Build.PL
    ./Build
    ./Build test
    ./Build install
    
Perl One-liners
---------------

These commands all assume the module has been successfully installed.

To see a list of defined presets use:

    perl -MCrypt::HSXKPasswd -e 'print join ", ", Crypt::HSXKPasswd->defined_presets(); print"\n";'
    
To see the details of a preset use a command of the form (replacing `WEB32` with which ever preset you want to view):

    perl -MCrypt::HSXKPasswd -e 'print Crypt::HSXKPasswd->new(preset => "WEB32")->status()."\n";'
    
To generate a password using a preset you can use a command of the form (replacing `WEB32` with which ever preset you want to view):

    perl -MCrypt::HSXKPasswd -e 'print hsxkpasswd(preset => "WEB32")."\n";'
    
Sample Perl File
----------------

This sample file assumes the module has been successfully installed.

    #!/usr/bin/perl
    
    use Crypt::HSXKPasswd;
    
    print hsxkpasswd(preset => 'WEB32')."\n";