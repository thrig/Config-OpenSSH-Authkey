#!/usr/bin/perl -w

use warnings;
use strict;

use Test::More tests => 8;
BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );

can_ok( 'Config::OpenSSH::Authkey',
  qw{new parse_file parse_fh parse_entry keys reset} );

my $ak = Config::OpenSSH::Authkey->new();
isa_ok( $ak, 'Config::OpenSSH::Authkey' );
ok( !@{ $ak->keys }, 'check that no keys exist' );

$ak->parse_file('t/authorized_keys');
ok( @{ $ak->keys } == 4, 'check that keys loaded' );

$ak->reset();
ok( !@{ $ak->keys }, 'check that no keys exist' );

open( my $fh, '<', 't/authorized_keys' )
  or diag("cannot open authkeys file: $!\n");
$ak->parse_fh( $fh, undef, 1 );
ok( @{ $ak->keys } == 3, 'check that keys loaded' );

exit 0;
