# -*- Perl -*-
#
# Methods to interact with OpenSSH authorized_keys file data.

package Config::OpenSSH::Authkey;

require 5.006;

use strict;
use warnings;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

use IO::Handle qw(getline);

our $VERSION = '0.52';

######################################################################
#
# Utility Methods - Internal

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
  my $class = shift;
  my $options_ref = shift || {};

  my $self = {
    _fh                  => undef,
    _keys                => [],
    _seen_keys           => {},
    _auto_store          => 0,
    _tag_dups            => 0,
    _nostore_nonkey_data => 0
  };

  for my $pref (qw/auto_store tag_dups nostore_nonkey_data/) {
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

sub fh {
  my $self = shift;
  my $fh = shift || croak('fh requires a filehandle');

  $self->{_fh} = $fh;
  return $self;
}

sub file {
  my $self = shift;
  my $file = shift || croak('file requires a file');

  my $fh;
  open( $fh, '<', $file ) or croak($!);
  $self->{_fh} = $fh;

  return $self;
}

sub iterate {
  my $self = shift;
  croak('no filehandle to iterate on') if !defined $self->{_fh};

  my $line = $self->{_fh}->getline;
  return defined $line ? $self->parse($line) : ();
}

sub consume {
  my $self = shift;
  croak('no filehandle to consume') if !defined $self->{_fh};

  my $old_auto_store = $self->auto_store();
  $self->auto_store(1);

  while ( my $line = $self->{_fh}->getline ) {
    $self->parse($line);
  }

  $self->auto_store($old_auto_store);

  return $self;
}

sub parse {
  my $self = shift;
  my $data = shift || croak('need data to parse');

  my $entry;

  if ( $data =~ m/^\s*(?:#|$)/ ) {
    chomp($data);
    $entry = Config::OpenSSH::Authkey::MetaEntry->new($data);
    if ( $self->{_auto_store} and !$self->{_nostore_nonkey_data} ) {
      push @{ $self->{_keys} }, $entry;
    }
  } else {
    $entry = Config::OpenSSH::Authkey::Entry->new($data);
    if ( $self->{_tag_dups} ) {
      if ( exists $self->{_seen_keys}->{ $entry->key } ) {
        $entry->duplicate_of( $self->{_seen_keys}->{ $entry->key } );
      } else {
        $self->{_seen_keys}->{ $entry->key } = $entry;
      }
    }
    push @{ $self->{_keys} }, $entry if $self->{_auto_store};
  }

  return $entry;
}

sub get_stored_keys {
  shift->{_keys};
}

sub reset_store {
  my $self = shift;
  $self->{_seen_keys} = {};
  $self->{_keys}      = [];
  return $self;
}

sub reset_dups {
  my $self = shift;
  $self->{_seen_keys} = {};
  return $self;
}

sub auto_store {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_auto_store} = $setting ? 1 : 0;
  }
  return $self->{_auto_store};
}

sub tag_dups {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_tag_dups} = $setting ? 1 : 0;
  }
  return $self->{_tag_dups};
}

sub nostore_nonkey_data {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_nostore_nonkey_data} = $setting ? 1 : 0;
  }
  return $self->{_nostore_nonkey_data};
}

1;

__END__

=head1 NAME

Config::OpenSSH::Authkey - interface to OpenSSH authorized_keys data

=head1 SYNOPSIS

  use Config::OpenSSH::Authkey ();
  my $ak = Config::OpenSSH::Authkey->new;
  
  TODO

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

Consult the L<"OPTIONS"> section for means to customize how
C<authorized_keys> data is handled.

=head1 METHODS

=over 4

=item B<new>

Constructor method. Accepts a hash reference containing L<"OPTIONS"> that
alter how the instance behaves.

  my $ak = Config::OpenSSH::Authkey->new({
    tag_dups => 1,
    nostore_nonkey_data => 1,
  });

=item B<fh>

Accepts a filehandle, stores this handle in the instance, for future use
by B<iterate> or B<consume>.

=item B<file>

Accepts a filename, attempts to open this file, and store the resulting
filehandle in the instance for future use by B<iterate> or B<consume>.
Throws an exception if the file cannot be opened.

=item B<iterate>

Returns the next entry of the filehandle (or, lacking a filehandle in
the instance, throws an error. Call B<fh> or B<file> first). Returned
data will either be C<Config::OpenSSH::Authkey::MetaEntry> (comments,
blank lines) or L<Config::OpenSSH::Authkey::Entry> (public key) objects.

For example, to exclude SSHv1 C<authorized_keys> data, while retaining
all other data in the file:

  while (my $entry = $ak->iterate) {
    if ($entry->can("prototol")) {
      next if $entry->protocol == 1;
    }
    
    print $output_fh $entry->as_string, "\n";
  }

=item B<consume>

This method consumes all data in the B<fh> or B<file> opened in the
instance, and saves it to the module key store. The B<auto_store> option
is temporarily enabled to allow this. Set the B<nostore_nonkey_data>
option to avoid saving non-key material to the key store. Stored keys
can be accessed by calling the B<get_stored_keys> method.

=item B<parse> I<data>

Attempts to parse input data, either as a comment or blank line with
C<Config::OpenSSH::Authkey::MetaEntry>, or as a public key via
L<Config::OpenSSH::Authkey::Entry>. Will throw an exception if the
public key cannot be parsed.

Returns either an C<Config::OpenSSH::Authkey::MetaEntry> or
L<Config::OpenSSH::Authkey::Entry> object.

=item B<get_stored_keys>

Instance method. Returns an array reference of any public keys stored in
the instance. B<keys> will only be populated if the B<auto_store> option
is enabled.

Keys will be either C<Config::OpenSSH::Authkey::MetaEntry> (comments,
blank lines) or L<Config::OpenSSH::Authkey::Entry> (public key) objects.
To avoid storing comments and blank lines, enable the
B<nostore_nonkey_data> option before calling B<iterate> or B<consume>.

=item B<reset_store>

Removes all C<authorized_keys> entries stored by the instance. Also
removes all the seen keys from the duplicate check stash.

=item B<reset_dups>

Removes all the seen keys from the duplicate check stash. This method is
likely useless if a custom code reference has been installed to handle
the duplicate key checks.

=back

=head1 OPTIONS

The following options can be specified as arguments in a hash reference
to the B<new> method, or by calling the option name as a method. All
options default to false. Pass a true value to enable.

=over 4

=item B<auto_store> I<boolean>

Whether to store parsed entries in the instance. The default is to not
store any entries.

=item B<tag_dups> I<boolean>

Whether to check for duplicate C<authorized_keys> keys. The default is
to not check for duplicate keys. If this option is enabled, the
B<duplicate_of> method of L<Config::OpenSSH::Authkey::Entry> should be
used to check whether a particular entry is a duplicate.

=item B<nostore_nonkey_data> I<boolean>

Whether to store non-key data (comments, blank lines) in the auto-store
data structure. The default is to store these lines. The B<iterate>
method always returns these lines, regardless of this setting.

=back

=head1 Config::OpenSSH::Authkey::MetaEntry

Utility class that stores blank lines or comments. Objects of this type
should only be created by the B<parse_fh> or B<parse_file> methods. The
object supports an B<as_string> method that will return the line.
Disable the parsing of this data by enabling the B<nostore_nonkey_data>
option prior to calling a B<parse_f*> method.

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
