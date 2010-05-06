# -*- Perl -*-
#
# Methods to interact with OpenSSH authorized_keys file data.
#
# TODO need to implement better exception handling (this module, or
# Authkey::Entry, or the duplicate checks?). Then some perldoc work,
# sample scripts to see if interface is nice...

package Config::OpenSSH::Authkey;

require 5.006;

use strict;
use warnings;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

our $VERSION = '0.10';

{
  # Utility class for comments or blank lines in authorized_keys files
  package Config::OpenSSH::Authkey::MetaEntry;

  sub new {
    my $class = shift;
    my $entry = shift;
    bless \$entry, $class;
  }

  sub as_string {
    ${ $_[0] };
  }
}

######################################################################
#
# Class methods

sub new {
  my $class       = shift;
  my $options_ref = shift;

  my $self = {
    _keys              => [],
    _seen_keys         => {},
    _auto_store        => 0,
    _kill_dups         => 0,
    _strip_nonkey_data => 0
  };

  for my $pref (qw/auto_store kill_dups strip_nonkey_data/) {
    if ( exists $options_ref->{$pref} ) {
      $self->{"_$pref"} = $options_ref->{$pref} ? 1 : 0;
    }
  }

  bless $self, $class;
  return $self;
}

######################################################################
#
# Instance methods

sub parse_file {
  my $self = shift;
  my $file = shift;

  my $fh;
  open( $fh, '<', $file ) or croak($!);

  return $self->parse_fh( $fh, @_ );
}

sub parse_fh {
  my ( $self, $fh, $callback_ref ) = @_;

  while ( my $line = <$fh> ) {
    my ( $entry, $type );
    if ( $line =~ m/^\s*(?:#|$)/ ) {
      if ( $self->{_strip_nonkey_data} ) {
        next;
      } else {
        $entry = Config::OpenSSH::Authkey::MetaEntry->new($line);
        $type  = 'metadata';
        if ( $self->{_auto_store} ) {
          push @{ $self->{_keys} }, $entry;
        }
      }
    } else {
      $entry = $self->parse_entry($line);
      $type  = 'pubkey';
    }

    if ( defined $callback_ref ) {
      eval { $callback_ref->( $type, $entry, $line ); };
      croak($@) if $@;
    }
  }

  return $self;
}

# Directly parse an authorized_keys line (or SSH public key data from
# somewhere).
sub parse_entry {
  my ( $self, $line ) = @_;

  my $entry = Config::OpenSSH::Authkey::Entry->new($line);

  if ( $self->{_kill_dups} ) {
    # TODO probably need better duplicate handling...
    undef $entry if $self->{_seen_keys}->{ $entry->key }++;
  }
  if ( $self->{_auto_store} ) {
    push @{ $self->{_keys} }, $entry if defined $entry;
  }

  return $entry;
}

sub keys {
  shift->{_keys};
}

sub reset {
  my $self = shift;
  $self->{_seen_keys} = {};
  $self->{_keys}      = [];
  return 1;
}

sub auto_store {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_auto_store} = $setting ? 1 : 0;
  }
  return $self->{_auto_store};
}

sub kill_dups {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_kill_dups} = $setting ? 1 : 0;
  }
  return $self->{_kill_dups};
}

sub strip_nonkey_data {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_strip_nonkey_data} = $setting ? 1 : 0;
  }
  return $self->{_strip_nonkey_data};
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey - interface to OpenSSH authorized_keys data

=head1 SYNOPSIS

  use Config::OpenSSH::Authkey ();
  my $ak = Config::OpenSSH::Authkey->new;

=head1 DESCRIPTION

This module provides an interface to the entries in an OpenSSH
C<authorzied_keys> file. Both SSH1 and SSH2 protocol public keys are
supported.
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
provides an interface to individual entries (lines) in the
C<authorzied_keys> file.

This is a pure Perl interface, so may differ from how OpenSSH parses the
C<authorzied_keys> data. The sshd(8) manual and OpenSSH 5.2 source code
were consulted in the creation of this module.

=head1 METHODS

=over 4

=item B<new>

Constructor method. Accepts no arguments.

=item B<parse_fh>

Instance method. TODO.

=item B<parse_file> I<filename>

Instance method. Accepts a filename (expansion of shell conventions such
as C<~> is not supported; use L<File::HomeDir|File::HomeDir> or similar
to perform that expansion), opens the file (or croaks), but otherwise
passes that filehandle and any remaining arguments over to B<parse_fh>.

=item B<parse_entry> I<line>

Instance method. Passes first argument directly to the
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
module.

Returns an
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
object. Throws an error if parsing fails.

=item B<keys>

Returns an array reference of any public keys parsed by a B<parse_*>
instance method, assuming such keys were populated by enabling the
B<auto_store> option.

=item B<reset>

Removes all C<authorized_keys> entries stored by the instance.

=item B<auto_store> I<boolean>

Whether to store parsed entries in the instance. Default is to not store
any entries.

=item B<kill_dups> I<boolean>

Whether to omit duplicate C<authorized_keys> keys. Default is to not
omit any duplicates. TODO if enabled, replacing object with C<undef>
which probably could be improved.

=item B<strip_nonkey_data> I<boolean>

Whether to strip out non-public key related material (blank lines and
comments from C<authorized_keys> files, typically) when processing input
via B<parse_file> or B<parse_fh>. Default is to not strip non-key data.

=back

=head1 BUGS

No known bugs. Newer versions of this module may be available from CPAN.

If the bug is in the latest version, send a report to the author.
Patches that fix problems or add new features are welcome.

=head1 SEE ALSO

sshd(8), L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>

=head1 AUTHOR

Jeremy Mates, E<lt>jmates@sial.orgE<gt>

=head1 COPYRIGHT

Copyright 2009-2010 by Jeremy Mates.

This program is free software; you can redistribute it and/or modify it
under the Artistic license.

=cut
