xkpasswd.pm
===========

A Perl module for generating secure memorable passwords inspired by the fabulous XKCD web comic. This is the library that drives www.xkpasswd.net

* Project Home Page: [www.bartb.ie/xkpasswd](http://www.bartb.ie/xkpasswd) - **please consider making a donation here**
* [Perl POD Documentation](http://bbusschots.github.io/xkpasswd.pm/pod.html)

This library is provided entirely free of charge under a very liberal free
licence. It has taken a signifficant amount of time to write, and continues to
take time to maintain and update. If you'd like to contribute towards that time
and efford please consider making a donation at the project's home page (linked above).

Quick Install Guide
-------------------

This guide assumes a Linux/Unix OS (including OS X) with Perl and GIT installed (Mac users will need to install the free XCode developer tools available in the Mac App Store to install GIT)

    $ cd /usr/local/
    $ sudo git clone https://github.com/bbusschots/xkpasswd.pm.git
    
Perl One-liners
---------------

These commands all assume XKPasswd was installed in `/usr/local/xkpasswd.pm/`, if you install it elsewhere, update the path within the commands.

To see a list of defined presets use:

    perl -e 'use lib "/usr/local/xkpasswd.pm/";use XKPasswd; print join ", ", XKPasswd->defined_presets(); print"\n";'

To see the details of a preset use a command of the form (replacing `WEB32` with which ever preset you want to view):

    perl -e 'use lib "/usr/local/xkpasswd.pm/";use XKPasswd; my $xkpasswd = XKPasswd->new("/usr/local/xkpasswd.pm/sample_dict.txt", "WEB32"); print $xkpasswd->status();'

To generate a password using a preset you can use a command of the form (replacing `WEB32` with which ever preset you want to view):

    perl -e 'use lib "/usr/local/xkpasswd.pm/";use XKPasswd; print xkpasswd("/usr/local/xkpasswd.pm/sample_dict.txt", "WEB32")."\n";'
    
Sample Perl File
----------------

This sample file assumes XKPasswd has been installed in `/usr/local/xkpasswd.pm/`, if you install it elsewhere, update the paths in the script accordingly.

    use lib '/usr/local/xkpasswd.pm/';
    use XKPasswd;
    
    print xkpasswd('/usr/local/xkpasswd.pm/sample_dict.txt', 'WEB32')."\n";