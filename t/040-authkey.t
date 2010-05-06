#!/usr/bin/perl
#
# Tests for Config::OpenSSH::Authkey and a utility
# Config::OpenSSH::Authkey::MetaEntry class.

use strict;
use warnings;

use Test::More tests => 18;

BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );

{
  can_ok( 'Config::OpenSSH::Authkey::MetaEntry', qw{new as_string} );

  my $test_line  = '# some comment';
  my $meta_entry = Config::OpenSSH::Authkey::MetaEntry->new($test_line);
  isa_ok( $meta_entry, 'Config::OpenSSH::Authkey::MetaEntry' );

  is( $meta_entry->as_string, $test_line, 'check MetaEntry as_string' );
}

eval {
  can_ok(
    'Config::OpenSSH::Authkey',
    qw/new parse_file parse_fh parse_entry keys reset
      auto_store kill_dups strip_nonkey_data/
  );

  my $ak = Config::OpenSSH::Authkey->new();
  isa_ok( $ak, 'Config::OpenSSH::Authkey' );
  ok( !@{ $ak->keys }, 'check that no keys exist' );

  my @prefs = qw/auto_store kill_dups strip_nonkey_data/;
  for my $pref (@prefs) {
    is( $ak->$pref, 0, "check default for $pref setting" );
  }

  # Confirm options can be passed to new()
  my $ak_opts = Config::OpenSSH::Authkey->new(
    { auto_store => 1, kill_dups => 1, strip_nonkey_data => 1 } );
  for my $pref (@prefs) {
    is( $ak_opts->$pref, 1, "check non-default for $pref setting" );
  }

  $ak->auto_store(1);
  $ak->strip_nonkey_data(1);
  is( $ak->auto_store, 1, 'check that auto_store setting updated' );

  $ak->parse_file('t/authorized_keys');
  is( scalar @{ $ak->keys }, 4, 'check that all keys loaded' );

  $ak->reset();
  ok( !@{ $ak->keys }, 'check that no keys exist' );

  $ak->kill_dups(1);

  open( my $fh, '<', 't/authorized_keys' )
    or diag("cannot open authkeys file: $!\n");
  $ak->parse_fh($fh);
  is( scalar @{ $ak->keys }, 3, 'check that keys loaded w/o dups' );

};
if ($@) {
  diag("Unexpected error: $@");
}

exit 0;
