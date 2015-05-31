use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Crypt::HSXKPasswd',
    license             => 'bsd',
    dist_abstract       => q{A secure memorable password generator inspired by Steve Gibson's Passord Haystacks (https://www.grc.com/haystack.htm), and the famous XKCD password cartoon (https://xkcd.com/936/).},
    dist_author         => q{Bart Busschots <bart@bartificer.net>},
    dist_version_from   => 'lib/Crypt/HSXKPasswd.pm',
    release_status      => 'testing',
    configure_requires => {
        'Module::Build' => 0,
    },
    build_requires => {
        'Test::More' => 0,
    },
    requires => {
        perl => '5.16.0',
        Carp => 0,
        DateTime => 0,
        'List::MoreUtils' => 0,
        'Math::BigInt' => 0,
        'Math::Round' => 0,
        'Params::Validate' => 0,
        'Scalar::Util' => 0,
        'Text::Unidecode' => 0,
        'Type::Tiny' => 0,
        'Type::Library' => 0,
        'Types::Standard' => 0,
        'Data::Dumper' => 0,
    },
    recommends => {
        'Data::Entropy::Algorithms' => 0,
        'Devel::StackTrace' => 0,
        'Email::Valid' => 0,
        JSON => 0,
        'LWP::UserAgent' => 0,
        'Math::Random::Secure' => 0,
        'Mozilla::CA' => 0,
        URI => 0,
    },
    add_to_cleanup     => [ 'Crypt-HSXKPasswd-*' ],
    create_makefile_pl => 'traditional',
    create_readme => 1,
);

$builder->create_build_script();
