#!/usr/bin/perl
#
# Tests for Config::OpenSSH::Authkey and a utility
# Config::OpenSSH::Authkey::MetaEntry class.

use strict;
use warnings;

use Test::More tests => 15;

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
    qw/new fh file iterate_fh consume_fh parse_entry
    iterate_store reset_store_iterator reset_store reset_dups
    auto_store check_dups strip_nonkey_data/
  );

  my $ak = Config::OpenSSH::Authkey->new();
  isa_ok( $ak, 'Config::OpenSSH::Authkey' );
#  ok( !@{ $ak->keys }, 'check that no keys exist' );
# TODO - may need new method to return count of keys in store? As
# only have an iterator now... or a "dump" or something to get
# all the keys instead.

  my @prefs = qw/auto_store check_dups strip_nonkey_data/;
  for my $pref (@prefs) {
    is( $ak->$pref, 0, "check default for $pref setting" );
  }

  # Confirm options can be passed to new()
  my $ak_opts = Config::OpenSSH::Authkey->new(
    { auto_store => 1, check_dups => 1, strip_nonkey_data => 1 } );
  for my $pref (@prefs) {
    is( $ak_opts->$pref, 1, "check non-default for $pref setting" );
  }

  $ak->auto_store(1);
  $ak->strip_nonkey_data(1);
  is( $ak->auto_store, 1, 'check that auto_store setting updated' );

  $ak->file('t/authorized_keys');
#  is( scalar @{ $ak->keys }, 4, 'check that all keys loaded' );
# TODO

  $ak->reset_store();
#  ok( !@{ $ak->keys }, 'check that no keys exist' );
# TODO

  $ak->check_dups(1);

  open( my $fh, '<', 't/authorized_keys' )
    or diag("cannot open authkeys file: $!\n");
  $ak->fh($fh);
#  is( scalar @{ $ak->keys }, 3, 'check that keys loaded w/o dups' );
# TODO - plus this will be 4, and one will pass $entry->duplicate_of

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
