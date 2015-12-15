HSXKPasswd
==========

A Perl module and terminal command for generating secure memorable passwords inspired by the Steve Gibson's Password Haystacks and the fabulous XKCD web comic. This is the library that drives www.xkpasswd.net

* Project Home Page: [www.bartb.ie/xkpasswd](http://www.bartb.ie/hsxkpasswd) - **please consider making a donation here**
* [CPAN Page](http://search.cpan.org/perldoc?Crypt%3A%3AHSXKPasswd)
* [Perl POD Documentation](http://bbusschots.github.io/hsxkpasswd/pod.html)

This library is provided entirely free of charge under a very liberal free
licence. It has taken a signifficant amount of time to write, and continues to
take time to maintain and update. If you'd like to contribute towards that time
and effort, please consider making a donation at the project's home page (linked above).

Quick Install Guide
-------------------

The latest stable release of this module is available via CPAN:

    sudo cpan Crypt::HSXKPasswd

You can manually build any version of the module by downloading the code and executing the following in the root directory of the download:

    perl Build.PL
    ./Build
    ./Build test
    ./Build install
    
If you prefer to install the module into your home directory rather than system-wide, you can do so with perlbrew. This is particularly useful if you do not have sudo access. You'll find instructions [in this blog post](https://www.bartbusschots.ie/s/2015/12/15/hsxkpasswd-without-sudo-with-perlbrew/).
    
Commandline Basics:
-------------------

Generate a single password with all the default settings:

    hsxkpasswd

Get a list of defined presets:

    hsxkpasswd -l
    
Generate 10 passwords from a preset:

    hsxkpasswd -p XKCD 10
    
Sample Perl File
----------------

This sample file assumes the module has been successfully installed.

    #!/usr/bin/perl
    
    use Crypt::HSXKPasswd;
    
    print hsxkpasswd(preset => 'WEB32')."\n";
