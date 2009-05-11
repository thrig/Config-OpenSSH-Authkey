#!/usr/bin/perl -w

use warnings;
use strict;

use Test::More tests => 4;
BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );

can_ok( 'Config::OpenSSH::Authkey', qw{new} );

exit 0;
