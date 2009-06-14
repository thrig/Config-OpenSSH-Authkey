# -*- Perl -*-

package Config::OpenSSH::Authkey;

require 5.006;

use warnings;
use strict;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

our $VERSION = '0.01';

# For (optional) duplicate suppression - TODO use tied hash if suitable
# module available?? Or just do it myself??
my %seen_keys;

sub new {
  my $class = shift;
  my $self = { _keys => [] };
  bless $self, $class;
  return $self;
}

# TODO load vs. parse or iterate to keep the API cleaner?

# TODO method to set duplicate handling (on/off/callback?)

sub parse_file {
  my $self = shift;
  my $file = shift;

  my $fh;
  open( $fh, '<', $file ) or croak($!);

  $self->parse_fh( $fh, @_ );
}

sub parse_fh {
  my ( $self, $fh, $callback_ref, $kill_dups ) = @_;

  if ( defined $callback_ref ) {
    croak('callback not a CODE reference') unless ref $callback_ref eq 'CODE';
  } else {
    $callback_ref = sub { shift eq 'pubkey' ? 1 : 0 };
  }
  $kill_dups = 0 if !defined $kill_dups;

  while ( my $line = <$fh> ) {
    if ( $line =~ m/^\s*(?:#|$)/ ) {
      $callback_ref->( 'metadata', $line );
    } else {
      eval {
        my $entry = Config::OpenSSH::Authkey::Entry->new($line);

        if ($kill_dups) {
          die "duplicate\n" if $seen_keys{ $entry->key }++;
        }

        if ( $callback_ref->( 'pubkey', $line, $@ ) ) {
          push @{ $self->{_keys} }, $entry;
        }
      };
      if ($@) {
        if ( $@ eq "duplicate\n" ) {
          $callback_ref->( 'duplicate', $line, $@ );
        } else {
          $callback_ref->( 'unknown', $line, $@ );
        }
      }
    }
  }

  return $self;
}

# Directly parse an authorized_keys line (or SSH public key data from
# somewhere). Will throw an error from Config::OpenSSH::Authkey::Entry
# if parsing fails.
sub parse_entry {
  my ( $self, $line, $kill_dups ) = @_;
  $kill_dups = 0 if !defined $kill_dups;

  my $entry = Config::OpenSSH::Authkey::Entry->new($line);

  if ($kill_dups) {
    die "duplicate\n" if $seen_keys{ $entry->key }++;
  }
  # TODO need option or callback to toggle this decision
  push @{ $self->{_keys} }, $entry;

  return $entry;
}

sub keys {
  shift->{_keys};
}

sub reset {
  shift->{_keys} = [];
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey - interface to OpenSSH authorized_keys

=head1 SYNOPSIS

  use Config::OpenSSH::Authkey ();
  my $ak = Config::OpenSSH::Authkey->new;

=head1 DESCRIPTION

This module provides an interface to the entries in an OpenSSH
C<authorzied_keys> file. Both SSH1 and SSH2 protocol public keys are
supported.
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
provides an interface to each parsed public key.

This is a pure Perl interface, so may differ from how OpenSSH parses the
C<authorzied_keys> data. The sshd(8) manual and OpenSSH 5.2 source code
were consulted in the creation of this module.

=head1 METHODS

=over 4

=item B<new>

Constructor method. Accepts no arguments.

=item B<parse_fh>

Instance method. Accepts a filehandle, an optional callback CODE
reference, an a boolean that if true will cause duplicate keys to
be skipped. TODO error handling??

If the callback CODE reference is C<undef> or not passed, all parsed
C<authorized_keys> entries will be stored in the object for future use.

Duplicates are checked for by the public key material. This may be a
different view than what OpenSSH considers a valid key, as OpenSSH will
use the first matching key that also has valid options, given two
identical entries where the first has invalid options set. As this
module does not yet parse option, the first matching public key wins,
not necessarily a subsequent duplicate key that has valid options set.

=item B<parse_file>

Instance method. Accepts a fully qualified filename (expansion of shell
type metacharacters such as C<~> is not supported; use
L<File::HomeDir|File::HomeDir> or similar to perform that expansion),
opens the file (or croaks), but otherwise passes that filehandle and any
remaining arguments up to B<parse_fh>.

=item B<parse_entry>

Instance method. Passes data presumed to be an C<authorized_keys> entry
directly to the
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
module. Useful if the C<authorized_keys> data resides in some other
source, such as a database, instead of on the filesystem.

Throws an error if parsing fails.

Returns an
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry> object.

=item B<keys>

Returns an array reference of any public keys parsed by a B<parse_*>
instance method.

=item B<reset>

=back

=head1 BUGS

No known bugs.

=head2 Reporting Bugs

Newer versions of this module may be available from CPAN.

If the bug is in the latest version, send a report to the author.
Patches that fix problems or add new features are welcome.

=head2 Known Issues

Note that parsing of OpenSSH authorized_keys options (C<command=""> and
so forth) beyond stashing them into a string is not yet supported. A
future version of this module may add better support for options.

=head1 SEE ALSO

sshd(8), L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>

=head1 AUTHOR

Jeremy Mates, E<lt>jmates@sial.orgE<gt>

=head1 COPYRIGHT

Copyright 2009 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
