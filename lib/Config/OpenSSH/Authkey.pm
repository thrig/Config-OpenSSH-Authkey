# -*- Perl -*-
#
# Methods to interact with OpenSSH authorized_keys file data.

package Config::OpenSSH::Authkey;

require 5.006;

use strict;
use warnings;

use Carp qw(croak);
use Config::OpenSSH::Authkey::Entry ();

our $VERSION = '0.50';

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
    _fh                => undef,
    _keys              => [],
    _key_position      => 0,
    _seen_keys         => {},
    _auto_store        => 0,
    _check_dups        => 0,
    _strip_nonkey_data => 0
  };

  for my $pref (qw/auto_store check_dups strip_nonkey_data/) {
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
  my $file = shift;

  my $fh;
  open( $fh, '<', $file ) or croak($!);
  $self->{_fh} = $fh;

  return $self;
}

sub iterate_fh {
  my $self = shift;
  croak('no filehandle to iterate on') if !defined $self->{_fh};

  my $line = $self->{_fh}->getline;
  my $entry;

  if ( defined $line ) {
    if ( $line =~ m/^\s*(?:#|$)/ ) {
      next if $self->{_strip_nonkey_data};
      chomp($line);
      $entry = Config::OpenSSH::Authkey::MetaEntry->new($line);
      push @{ $self->{_keys} }, $entry if $self->{_auto_store};
    } else {
      $entry = $self->parse_entry($line);
    }
  }

  return $entry;
}

sub consume_fh {
  my $self = shift;

  my $old_auto_store = $self->auto_store();
  $self->auto_store(1);

  my $entry;
  do $self->iterate until !defined $entry;

  $self->auto_store($old_auto_store);

  return $self;
}

sub parse_entry {
  my ( $self, $line ) = @_;

  my $entry = Config::OpenSSH::Authkey::Entry->new($line);

  if ( $self->{_check_dups} ) {
    if ( exists $self->{_seen_keys}->{ $entry->key } ) {
      $entry->duplicate_of( $self->{_seen_keys}->{ $entry->key } );
    } else {
      $self->{_seen_keys}->{ $entry->key } = $entry;
    }
  }
  push @{ $self->{_keys} }, $entry if $self->{_auto_store};

  return $entry;
}

sub iterate_store {
  my $self = shift;
  return $self->{_key_position} > $#{ $self->{_keys} }
    ? undef
    : $self->{_keys}->[ $self->{_key_position}++ ];
}

sub reset_store_iterator {
  my $self = shift;
  $self->{_key_position} = 0;
  return $self;
}

sub reset_store {
  my $self = shift;
  $self->{_seen_keys}    = {};
  $self->{_keys}         = [];
  $self->{_key_position} = 0;
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

sub check_dups {
  my $self    = shift;
  my $setting = shift;
  if ( defined $setting ) {
    $self->{_check_dups} = $setting ? 1 : 0;
  }
  return $self->{_check_dups};
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
alter how the instance behaves when processing C<authorized_keys>. The
hash reference can also contain various L<"CALLBACKS"> that can customize
how duplicates are detected.

  my $ak = Config::OpenSSH::Authkey->new({
    check_dups => 1,
    strip_nonkey_data => 1
  });

=item B<parse_fh> I<filehandle>, I<optional code ref>

Instance method. Accepts a filehandle, and iterates over the
contents of that handle. This method will throw an exception should
something go wrong.

Duplicate handling is done in the B<parse_entry> method, which is called
by this method for each line that might be a public key. See
L<"OPTIONS"> for settings that influence what B<parse_fh> does.

If passed a code reference, this method will invoke that reference for
each (non-duplicate) entry found in the file. The only argument to this
reference will either be a C<Config::OpenSSH::Authkey::MetaEntry>
(comments, blank lines) object, or a L<Config::OpenSSH::Authkey::Entry>
(public key) object. To skip comments and blank lines, enable the
B<strip_nonkey_data> option prior to calling B<parse_fh>.

An example callback that strips any SSHv1 keys:

  $ak->parse_fh($input_fh, sub {
    my $entry = shift;
    
    if ($entry->can("key")) {
      return if $entry->protocol == 1;
    }
    
    print $output_fh $entry->as_string;
  });

=item B<parse_file> I<filename>

Instance method. Accepts a filename, and opens that file (or croaks on
failure), but otherwise passes the resulting filehandle (and any
remaining arguments) to the B<parse_fh> method.

Use L<File::HomeDir|File::HomeDir> or similar if expansion of shell-type
constructs (C<~> for a home directory) is required.

=item B<parse_entry> I<line>

Instance method. Passes first argument directly to the
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
module. Returns an
L<Config::OpenSSH::Authkey::Entry|Config::OpenSSH::Authkey::Entry>
object, or C<undef> if an entry was a duplicate of a previous entry.
Throws an error if parsing fails.

This method is also called by the B<parse_file> and B<parse_fh> methods
while looping over entries in a file, and is where the
B<check_duplicate> L<"CALLBACKS"> handling occurs.

=item B<keys>

Instance method. Returns an array reference of any public keys parsed by
a B<parse_*> instance method. B<keys> will only be populated if the
B<auto_store> option is enabled.

Keys will be either C<Config::OpenSSH::Authkey::MetaEntry> (comments,
blank lines) or L<Config::OpenSSH::Authkey::Entry> (public key) objects.
To avoid storing comments and blank lines, enable the
B<strip_nonkey_data> option prior to using the B<parse_f*> methods.

=item B<reset>

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

=item B<check_dups> I<boolean>

Whether to check for duplicate C<authorized_keys> keys. The default is
to not check for duplicate keys. If this option is enabled, the
B<duplicate_of> method of L<Config::OpenSSH::Authkey::Entry> should be
used to check whether a particular entry is a duplicate.

=item B<strip_nonkey_data> I<boolean>

Whether to strip out non-public key related material (blank lines and
comments from C<authorized_keys> files, typically) when processing
input via B<parse_file> or B<parse_fh>. The default is to not strip
non-key data.

=back

=head1 Config::OpenSSH::Authkey::MetaEntry

Utility class that stores blank lines or comments. Objects of this type
should only be created by the B<parse_fh> or B<parse_file> methods. The
object supports an B<as_string> method that will return the line.
Disable the parsing of this data by enabling the B<strip_nonkey_data>
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
