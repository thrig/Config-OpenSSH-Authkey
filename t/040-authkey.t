#!/usr/bin/perl
#
# Tests for Config::OpenSSH::Authkey and a utility
# Config::OpenSSH::Authkey::MetaEntry class.

use strict;
use warnings;

use Test::More tests => 19;

BEGIN { use_ok('Config::OpenSSH::Authkey') }
ok( defined $Config::OpenSSH::Authkey::VERSION, '$VERSION defined' );

# Utility class tests
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
    qw/new fh file iterate consume parse_entry
      get_stored_keys reset_store reset_dups
      auto_store check_dups nostore_nonkey_data/
  );

  my $ak = Config::OpenSSH::Authkey->new();
  isa_ok( $ak, 'Config::OpenSSH::Authkey' );
  ok( !@{ $ak->get_stored_keys }, 'check that no keys exist' );

  my @prefs = qw/auto_store check_dups nostore_nonkey_data/;
  for my $pref (@prefs) {
    is( $ak->$pref, 0, "check default for $pref setting" );
  }

  # Confirm options can be passed to new()
  my $ak_opts = Config::OpenSSH::Authkey->new(
    { auto_store => 1, check_dups => 1, nostore_nonkey_data => 1 } );
  for my $pref (@prefs) {
    is( $ak_opts->$pref, 1, "check non-default for $pref setting" );
  }

  $ak->auto_store(1);
  $ak->nostore_nonkey_data(1);
  is( $ak->auto_store, 1, 'check that auto_store setting updated' );

  $ak->file('t/authorized_keys')->consume;
  is( scalar @{ $ak->get_stored_keys }, 4, 'check that all keys loaded' );

  $ak->reset_store();
  ok( !@{ $ak->get_stored_keys }, 'check that no keys exist' );

  $ak->check_dups(1);

  open( my $fh, '<', 't/authorized_keys' )
    or diag("cannot open authkeys file: $!\n");
  $ak->fh($fh)->consume;
  is( scalar @{ $ak->get_stored_keys }, 4, 'check that keys loaded again' );

};
if ($@) {
  diag("Unexpected exception: $@");
}

eval {
  my $ak = Config::OpenSSH::Authkey->new();
  $ak->parse_entry('not a pubkey');
};
like( $@, qr/unable to parse public key/, "invalid pubkey error" );

exit 0;
